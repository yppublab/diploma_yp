#!/usr/bin/env python3
import argparse
import base64
import csv
import os
import subprocess
import sys


def normalize_header(value):
    return " ".join(value.strip().lower().split())


def run_cmd(args, input_text=None, check=True):
    proc = subprocess.run(
        args,
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        msg = "Command failed: {}\nstdout:\n{}\nstderr:\n{}".format(
            " ".join(args), proc.stdout, proc.stderr
        )
        raise RuntimeError(msg)
    return proc


def ldap_base_args(uri, bind_dn, bind_password):
    return ["-x", "-H", uri, "-D", bind_dn, "-w", bind_password]


def parse_ldif(text):
    """Парсит LDIF с поддержкой base64 encoded значений (::)."""
    entries = []
    current = None
    lines = []
    
    for line in text.splitlines():
        if line.startswith(" "):
            if lines:
                lines[-1] += line[1:]
            else:
                lines.append(line)
        else:
            lines.append(line)
    
    for line in lines:
        if not line.strip():
            if current:
                entries.append(current)
                current = None
            continue
        if current is None:
            current = {"dn": None, "attrs": {}}
        if line.startswith("dn: "):
            current["dn"] = line.split("dn: ", 1)[1].strip()
        elif line.startswith("dn:: "):
            b64 = line.split("dn:: ", 1)[1].strip()
            try:
                current["dn"] = base64.b64decode(b64).decode("utf-8")
            except Exception:
                continue
        elif ":: " in line:
            key, val = line.split(":: ", 1)
            key = key.strip()
            try:
                val = base64.b64decode(val.strip()).decode("utf-8")
            except Exception:
                val = ""
            current["attrs"].setdefault(key, []).append(val.strip())
        elif ": " in line:
            key, val = line.split(": ", 1)
            key = key.strip()
            current["attrs"].setdefault(key, []).append(val.strip())
    
    if current:
        entries.append(current)
    return entries


def ldapsearch_by_dn(uri, bind_dn, bind_password, member_dn, attrs):
    """
    Поиск по DN как базе (scope base), а не как фильтру.
    Это избегает проблем с экранированием специальных символов в DN.
    """
    args = ["ldapsearch"] + ldap_base_args(uri, bind_dn, bind_password) + [
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-b",
        member_dn,
        "-s",
        "base",
        "(objectClass=*)",
    ] + attrs
    proc = run_cmd(args, check=False)
    if proc.returncode != 0 and "No such object" not in proc.stderr:
        return None
    entries = parse_ldif(proc.stdout)
    return entries[0] if entries else None


def ldapsearch_entries(uri, bind_dn, bind_password, base_dn, scope, ldap_filter, attrs):
    args = ["ldapsearch"] + ldap_base_args(uri, bind_dn, bind_password) + [
        "-LLL",
        "-o",
        "ldif-wrap=no",
        "-b",
        base_dn,
        "-s",
        scope,
        ldap_filter,
    ] + attrs
    proc = run_cmd(args, check=False)
    if proc.returncode != 0 and "No such object" not in proc.stderr:
        raise RuntimeError(
            "ldapsearch failed (rc={}):\n{}".format(proc.returncode, proc.stderr)
        )
    return parse_ldif(proc.stdout)


def extract_ou_path_from_dn(dn):
    """Извлекает OU путь из DN как список."""
    parts = dn.split(",")
    ou_parts = []
    for part in parts:
        part = part.strip()
        if part.lower().startswith("ou="):
            ou_parts.append(part.split("=", 1)[1].strip())
    return ou_parts


def extract_ou_string_from_dn(dn):
    """Извлекает OU путь из DN как строку."""
    ou_parts = extract_ou_path_from_dn(dn)
    if ou_parts:
        return "OU=" + ",OU=".join(ou_parts)
    return ""


def extract_cn_from_dn(dn):
    """Извлекает CN из DN."""
    parts = dn.split(",")
    for part in parts:
        part = part.strip()
        if part.lower().startswith("cn="):
            return part.split("=", 1)[1].strip()
    return ""


def is_placeholder_member(cn):
    """Проверяет, является ли запись служебным placeholder."""
    if not cn:
        return False
    return cn.lower() in ("group-placeholder", "placeholder", "ldap-placeholder")


def is_user_dn(dn):
    """Проверяет, находится ли DN в пользовательском OU."""
    dn_lower = dn.lower()
    ou_path = extract_ou_path_from_dn(dn)
    ou_path_lower = [ou.lower() for ou in ou_path]
    
    if "users" in ou_path_lower:
        return True
    if "disabled accounts" in dn_lower:
        return True
    if "service accounts" in dn_lower:
        return True
    
    return False


def is_group_dn(dn):
    """Проверяет, находится ли DN в групповом OU."""
    ou_path = extract_ou_path_from_dn(dn)
    ou_path_lower = [ou.lower() for ou in ou_path]
    return "groups" in ou_path_lower


def is_resource_group_dn(dn):
    """Проверяет, является ли группа ресурсной (OU=RES)."""
    ou_path = extract_ou_path_from_dn(dn)
    ou_path_lower = [ou.lower() for ou in ou_path]
    return "res" in ou_path_lower


def is_general_group_dn(dn):
    """Проверяет, является ли группа общей (не ресурсной)."""
    if not is_group_dn(dn):
        return False
    if is_resource_group_dn(dn):
        return False
    return True


def get_member_info(uri, bind_dn, bind_password, base_dn, member_dn, cache):
    """
    Определяет тип члена группы и получает uid из LDAP.
    """
    if member_dn in cache:
        return cache[member_dn]
    
    cn = extract_cn_from_dn(member_dn)
    
    if is_placeholder_member(cn):
        info = {"type": "placeholder", "cn": cn, "dn": member_dn, "uid": ""}
        cache[member_dn] = info
        return info
    
    if is_group_dn(member_dn):
        info = {"type": "group", "cn": cn, "dn": member_dn, "uid": ""}
        cache[member_dn] = info
        return info
    
    if is_user_dn(member_dn):
        entry = ldapsearch_by_dn(
            uri, bind_dn, bind_password, member_dn, ["uid", "cn"]
        )
        
        if entry:
            uid_list = entry["attrs"].get("uid", [])
            cn_list = entry["attrs"].get("cn", [])
            uid = uid_list[0] if uid_list else cn
            cn = cn_list[0] if cn_list else cn
        else:
            uid = cn
        
        info = {"type": "user", "cn": cn, "dn": member_dn, "uid": uid}
        cache[member_dn] = info
        return info
    
    info = {"type": "group", "cn": cn, "dn": member_dn, "uid": ""}
    cache[member_dn] = info
    return info


def print_table(rows, columns):
    if not rows:
        return
    widths = []
    for key, label in columns:
        max_len = len(label)
        for row in rows:
            val = str(row.get(key, ""))
            if len(val) > max_len:
                max_len = len(val)
        widths.append(max_len)
    header = " | ".join(label.ljust(widths[i]) for i, (_, label) in enumerate(columns))
    sep = "-+-".join("-" * widths[i] for i in range(len(columns)))
    print(header)
    print(sep)
    for row in rows:
        line = " | ".join(
            str(row.get(key, "")).ljust(widths[i]) for i, (key, _) in enumerate(columns)
        )
        print(line)


def main():
    parser = argparse.ArgumentParser(
        description="Export LDAP groups to CSV with member information."
    )
    parser.add_argument(
        "--output",
        default="ldap_groups_export.csv",
        help="Path to output CSV file.",
    )
    parser.add_argument("--ldap-uri", default="ldap://127.0.0.1")
    parser.add_argument("--base-dn", default="dc=local,dc=host")
    parser.add_argument("--bind-dn", default=None)
    parser.add_argument("--bind-password", default=None)
    parser.add_argument(
        "--ou-filter",
        default=None,
        help="Filter by OU (e.g., 'OU=Groups'). Export all if not specified.",
    )
    parser.add_argument(
        "--include-members",
        action="store_true",
        default=True,
        help="Include member information in export.",
    )
    parser.add_argument(
        "--separate-files",
        action="store_true",
        help="Create separate files for general groups and resource groups.",
    )
    parser.add_argument(
        "--exclude-placeholder",
        action="store_true",
        default=True,
        help="Exclude group-placeholder from children list.",
    )
    args = parser.parse_args()

    bind_dn = args.bind_dn or "cn=admin,{}".format(args.base_dn)
    bind_password = (
        args.bind_password
        or os.environ.get("LDAP_ADMIN_PASSWORD")
        or os.environ.get("LDAP_CONFIG_PASSWORD")
    )
    if not bind_password:
        print("Missing bind password (use --bind-password or LDAP_ADMIN_PASSWORD).")
        return 2

    group_filter = "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
    
    if args.ou_filter:
        search_base = args.ou_filter + "," + args.base_dn if args.ou_filter and args.ou_filter not in args.base_dn else args.base_dn
    else:
        search_base = args.base_dn

    print("Searching for groups in: {}".format(search_base))
    
    entries = ldapsearch_entries(
        args.ldap_uri,
        bind_dn,
        bind_password,
        search_base,
        "sub",
        group_filter,
        ["dn", "cn", "gidNumber", "description", "member", "objectClass"],
    )

    if not entries:
        print("No groups found.")
        return 0

    print("Found {} groups.".format(len(entries)))

    member_cache = {}
    rows = []
    general_groups = []
    res_groups = []
    
    stats = {
        "total_groups": 0,
        "general_groups": 0,
        "res_groups": 0,
        "groups_with_users": 0,
        "groups_with_children": 0,
        "total_users_found": 0,
        "total_children_found": 0,
        "ou_counts": {},
        "member_types": {"user": 0, "group": 0, "placeholder": 0, "unknown": 0},
    }

    for idx, entry in enumerate(entries, start=1):
        dn = entry.get("dn", "")
        attrs = entry.get("attrs", {})
        
        cn_list = attrs.get("cn", [])
        cn = cn_list[0] if cn_list else extract_cn_from_dn(dn)
        
        gid_list = attrs.get("gidNumber", [])
        gid = gid_list[0] if gid_list else ""
        
        desc_list = attrs.get("description", [])
        desc = desc_list[0] if desc_list else ""
        
        member_list = attrs.get("member", [])
        
        ou_path = extract_ou_string_from_dn(dn)
        
        is_res = is_resource_group_dn(dn)
        is_general = is_general_group_dn(dn)
        
        ou_key = ou_path if ou_path else "(no OU)"
        stats["ou_counts"][ou_key] = stats["ou_counts"].get(ou_key, 0) + 1
        
        children = []
        users_cn = []
        users_uid = []
        
        if args.include_members and member_list:
            for member_dn in member_list:
                member_dn = member_dn.strip()
                if not member_dn:
                    continue
                
                info = get_member_info(
                    args.ldap_uri, bind_dn, bind_password, args.base_dn, member_dn, member_cache
                )
                
                stats["member_types"][info["type"]] = stats["member_types"].get(info["type"], 0) + 1
                
                if args.exclude_placeholder and info["type"] == "placeholder":
                    continue
                
                if info["type"] == "group":
                    children.append(info["cn"])
                    stats["total_children_found"] += 1
                elif info["type"] == "user":
                    users_cn.append(info["cn"])
                    users_uid.append(info["uid"])
                    stats["total_users_found"] += 1
        
        children_str = ", ".join(children) if children else "(пусто)"
        users_cn_str = ", ".join(users_cn) if users_cn else "(пусто)"
        users_uid_str = ", ".join(users_uid) if users_uid else "(пусто)"
        
        if users_uid:
            stats["groups_with_users"] += 1
        if children and children_str != "(пусто)":
            stats["groups_with_children"] += 1
        
        real_member_count = len(member_list)
        if args.exclude_placeholder:
            real_member_count = sum(1 for m in member_list if not is_placeholder_member(extract_cn_from_dn(m)))
        
        row = {
            "gid": gid,
            "group": cn,
            "ou": ou_path,
            "children": children_str,
            "users_cn": users_cn_str,
            "users_uid": users_uid_str,
            "description": desc,
            "dn": dn,
            "member_count": real_member_count,
            "user_count": len(users_uid),
        }
        
        rows.append(row)
        stats["total_groups"] += 1
        
        if is_res:
            res_groups.append(row)
            stats["res_groups"] += 1
        elif is_general:
            general_groups.append(row)
            stats["general_groups"] += 1

    print("\n" + "="*60)
    print("EXPORT SUMMARY")
    print("="*60)
    
    print("\n📊 GROUP STATISTICS:")
    print_table(
        [
            {"metric": "Total groups", "count": stats["total_groups"]},
            {"metric": "General groups", "count": stats["general_groups"]},
            {"metric": "Resource groups", "count": stats["res_groups"]},
            {"metric": "Groups with users", "count": stats["groups_with_users"]},
            {"metric": "Groups with children", "count": stats["groups_with_children"]},
        ],
        [("metric", "Metric"), ("count", "Count")],
    )
    
    print("\n👥 MEMBER STATISTICS:")
    print_table(
        [
            {"type": "Users", "count": stats["total_users_found"]},
            {"type": "Nested groups", "count": stats["total_children_found"]},
            {"type": "Placeholders", "count": stats["member_types"].get("placeholder", 0)},
        ],
        [("type", "Type"), ("count", "Count")],
    )
    
    print("\n📁 GROUPS BY OU:")
    ou_rows = [{"ou": ou, "count": count} for ou, count in sorted(stats["ou_counts"].items())]
    print_table(ou_rows, [("ou", "OU"), ("count", "Count")])

    if args.separate_files:
        if general_groups:
            general_path = args.output.replace(".csv", "_general.csv")
            with open(general_path, "w", newline="", encoding="utf-8-sig") as f:
                # 🔧 ИЗМЕНЕНО: Children → Child_groups в заголовке CSV
                fieldnames = ["GID", "Group", "OU", "Child_groups", "Users_CN", "Users_UID", "Description"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for row in general_groups:
                    writer.writerow({
                        "GID": row["gid"],
                        "Group": row["group"],
                        "OU": row["ou"],
                        "Child_groups": row["children"],
                        "Users_CN": row["users_cn"],
                        "Users_UID": row["users_uid"],
                        "Description": row["description"],
                    })
            print("\n✅ General groups exported to: {}".format(general_path))
        
        if res_groups:
            res_path = args.output.replace(".csv", "_res.csv")
            with open(res_path, "w", newline="", encoding="utf-8-sig") as f:
                # 🔧 ИЗМЕНЕНО: Children → Child_groups в заголовке CSV
                fieldnames = ["GID", "Group", "OU", "Child_groups", "Users_CN", "Users_UID"]
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for row in res_groups:
                    writer.writerow({
                        "GID": row["gid"],
                        "Group": row["group"],
                        "OU": row["ou"],
                        "Child_groups": row["children"],
                        "Users_CN": row["users_cn"],
                        "Users_UID": row["users_uid"],
                    })
            print("✅ Resource groups exported to: {}".format(res_path))
    else:
        with open(args.output, "w", newline="", encoding="utf-8-sig") as f:
            # 🔧 ИЗМЕНЕНО: Children → Child_groups в заголовке CSV
            fieldnames = ["GID", "Group", "OU", "Child_groups", "Users_CN", "Users_UID", "Description", "DN", "MemberCount"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    "GID": row["gid"],
                    "Group": row["group"],
                    "OU": row["ou"],
                    "Child_groups": row["children"],
                    "Users_CN": row["users_cn"],
                    "Users_UID": row["users_uid"],
                    "Description": row["description"],
                    "DN": row["dn"],
                    "MemberCount": row["member_count"],
                })
        print("\n✅ All groups exported to: {}".format(args.output))

    print("\n📋 SAMPLE GROUPS WITH USERS (first 10):")
    sample_rows = [r for r in rows if r["user_count"] > 0][:10]
    if sample_rows:
        print_table(
            sample_rows,
            [
                ("group", "Group"),
                ("ou", "OU"),
                ("users_uid", "Users (UID)"),
                ("users_cn", "Users (CN)"),
                ("user_count", "Count"),
            ],
        )

    print("\n📋 SAMPLE GROUPS WITH CHILD_GROUPS (first 10):")
    sample_rows = [r for r in rows if r["children"] != "(пусто)"][:10]
    if sample_rows:
        print_table(
            sample_rows,
            [
                ("group", "Group"),
                ("ou", "OU"),
                ("children", "Child_groups"),
                ("user_count", "Direct Users"),
            ],
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())