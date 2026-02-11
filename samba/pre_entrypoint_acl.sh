#!/usr/bin/env bash

set -o pipefail

log() {
    echo "[acl-setup] $*"
}

SSSD_CONF=${SSSD_CONF:-/etc/sssd/sssd.conf}
if [[ ! -f "${SSSD_CONF}" && -f /etc/sssd_temp.conf ]]; then
    SSSD_CONF=/etc/sssd_temp.conf
fi

get_sssd_value() {
    local key="$1"
    awk -v k="$key" '
        $0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
            sub("^[[:space:]]*"k"[[:space:]]*=[[:space:]]*", "", $0)
            print $0
            exit
        }' "${SSSD_CONF}" 2>/dev/null | tr -d '\r'
}

LDAP_URI=${LDAP_URI:-$(get_sssd_value ldap_uri)}
LDAP_BASE=${LDAP_BASE:-$(get_sssd_value ldap_group_search_base)}
if [[ -z "${LDAP_BASE}" ]]; then
    LDAP_BASE=$(get_sssd_value ldap_search_base)
fi
LDAP_BINDDN=${LDAP_BINDDN:-$(get_sssd_value ldap_default_bind_dn)}
LDAP_BINDPW=${LDAP_BINDPW:-$(get_sssd_value ldap_default_authtok)}

if [[ -z "${LDAP_URI}" || -z "${LDAP_BASE}" || -z "${LDAP_BINDDN}" || -z "${LDAP_BINDPW}" ]]; then
    log "Missing LDAP settings (uri/base/binddn/bindpw)."
    exit 1
fi

if ! command -v ldapsearch >/dev/null 2>&1; then
    log "ldapsearch not found."
    exit 1
fi

if ! command -v setfacl >/dev/null 2>&1; then
    log "setfacl not found."
    exit 1
fi

if ! command -v getfacl >/dev/null 2>&1; then
    log "getfacl not found."
    exit 1
fi

SHARE_ROOT=${SAMBA_SHARE_PATH:-/share}
RES_OU="OU=RES"
res_dn="${RES_OU}"
if [[ "${res_dn,,}" != *"${LDAP_BASE,,}"* ]]; then
    res_dn="${res_dn},${LDAP_BASE}"
fi
echo "RES DN = ${res_dn}"
echo "LDAP_BASE: ${LDAP_BASE}"

ACL_SUPPORTED=1
acl_test="${SHARE_ROOT}/.acl_test.$$"
touch "${acl_test}" >/dev/null 2>&1 || ACL_SUPPORTED=0
if [[ ${ACL_SUPPORTED} -eq 1 ]]; then
    if ! setfacl -m u:root:rw "${acl_test}" 2> /tmp/acl_err.$$; then
        if grep -qi "Operation not supported" /tmp/acl_err.$$; then
            ACL_SUPPORTED=0
            log "ACL not supported on ${SHARE_ROOT}; skipping setfacl."
        else
            ACL_SUPPORTED=0
            log "ACL check failed; skipping setfacl."
        fi
    fi
    rm -f /tmp/acl_err.$$
fi
rm -f "${acl_test}" >/dev/null 2>&1

log "Searching resource groups in ${res_dn}..."
log "ldapsearch cmd: ldapsearch -x -H \"${LDAP_URI}\" -D \"${LDAP_BINDDN}\" -w \"***\" -LLL -b \"${res_dn}\" -s one \"(cn=SG-RES-SHARE-*)\" cn"
group_lines=$(ldapsearch -x -H "${LDAP_URI}" -D "${LDAP_BINDDN}" -w "${LDAP_BINDPW}" \
    -LLL -b "${res_dn}" -s one "(cn=SG-RES-SHARE-*)" cn 2>/dev/null)
rc=$?

rows=()
add_row() {
    rows+=("$1|$2|$3|$4|$5|$6")
}

if [[ $rc -ne 0 ]]; then
    add_row "-" "-" "-" "-" "ldap-error" "ldapsearch failed (rc=${rc})"
else
    mapfile -t groups < <(printf '%s\n' "${group_lines}" | awk -F': ' '/^cn: /{print $2}' | sort -u)

    if [[ ${#groups[@]} -eq 0 ]]; then
        add_row "-" "-" "-" "-" "no-groups" "no SG-RES-SHARE-* groups found"
    fi

    for group in "${groups[@]}"; do
        if [[ "${group}" =~ ^SG-RES-SHARE-(.+)-(RO|RW)$ ]]; then
            share_name="${BASH_REMATCH[1]}"
            access="${BASH_REMATCH[2]}"
        else
            add_row "-" "${group}" "-" "-" "skipped" "unexpected group name"
            continue
        fi

        share_path="${SHARE_ROOT}/${share_name}"
        if [[ ! -d "${share_path}" ]]; then
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "missing-dir" "folder not found"
            continue
        fi

        if ! getent group "${group}" >/dev/null 2>&1; then
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "missing-group" "group not in NSS"
            continue
        fi

        if [[ ${ACL_SUPPORTED} -eq 0 ]]; then
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "acl-unsupported" "filesystem does not support ACLs"
            continue
        fi

        if [[ "${access}" == "RO" ]]; then
            perm="rx"
            expected="r-x"
        else
            perm="rwx"
            expected="rwx"
        fi

        err=""
        setfacl -m "g:${group}:${perm}" "${share_path}" 2> /tmp/acl_err.$$ || err="setfacl failed"
        setfacl -m "d:g:${group}:${perm}" "${share_path}" 2>> /tmp/acl_err.$$ || err="setfacl failed"

        if [[ -n "${err}" ]]; then
            detail=$(tail -n 1 /tmp/acl_err.$$ 2>/dev/null)
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "acl-error" "${detail:-setfacl failed}"
            rm -f /tmp/acl_err.$$
            continue
        fi
        rm -f /tmp/acl_err.$$

        perm_line=$(getfacl -p "${share_path}" | awk -v g="${group}" '$0 ~ "^group:"g":" {print $0; exit}')
        def_line=$(getfacl -p "${share_path}" | awk -v g="${group}" '$0 ~ "^default:group:"g":" {print $0; exit}')
        perm_actual="${perm_line##*:}"
        def_actual="${def_line##*:}"

        if [[ "${perm_actual}" == "${expected}" && "${def_actual}" == "${expected}" ]]; then
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "acl-ok" "entry + default set"
        elif [[ "${perm_actual}" == "${expected}" ]]; then
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "acl-partial" "default missing/other"
        else
            add_row "${share_name}" "${group}" "${access}" "${share_path}" "acl-mismatch" "perm=${perm_actual:-?} def=${def_actual:-?}"
        fi
    done
fi

header="Share|Group|Access|Path|Status|Detail"
if command -v column >/dev/null 2>&1; then
    { echo "${header}"; printf '%s\n' "${rows[@]}"; } | column -t -s '|'
else
    echo "${header}"
    printf '%s\n' "${rows[@]}"
fi
