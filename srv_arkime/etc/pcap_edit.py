import argparse
import calendar
import configparser
import io
import logging
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple


def ensure_scapy() -> None:
    try:
        import scapy  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    venv_root = Path("/opt/arkime/venv")
    lib_dir = venv_root / "lib"
    if lib_dir.is_dir():
        for py_dir in lib_dir.iterdir():
            if py_dir.is_dir() and py_dir.name.startswith("python"):
                site = py_dir / "site-packages"
                if site.is_dir():
                    sys.path.insert(0, str(site))
                    break

    try:
        import scapy  # noqa: F401
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "scapy not found. Install it into /opt/arkime/venv or system python."
        ) from exc


ensure_scapy()

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

# Keep payload length unchanged to avoid TCP stream desync.
DEFAULT_DATE_OLD = "Date: Wed, 21 Jan 2026 17:06:10 GMT"
DEFAULT_TZ_OLD = "Timezone: Wed Jan 21 2026 17:06:10 GMT+0000"

DATE_RE = re.compile(
    br"Date: [A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT"
)
TZ_RE = re.compile(
    br"Timezone: [A-Za-z]{3} [A-Za-z]{3} \d{2} \d{4} \d{2}:\d{2}:\d{2} GMT\+0000"
)


def target_epoch(mode: str) -> float:
    if mode == "none":
        return 0.0
    if mode == "now":
        return time.time()
    if mode == "today-00":
        local = datetime.now().astimezone()
        local_midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
        return local_midnight.timestamp()
    if mode.startswith("epoch:"):
        return float(mode.split(":", 1)[1])
    raise ValueError("shift must be none, now, today-00, or epoch:<unix>")


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def has_recent_pcap_activity(pcap_dir: Path, max_age_seconds: int, min_size_bytes: int) -> bool:
    if not pcap_dir.is_dir():
        return False
    now = time.time()
    for path in pcap_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        if stat.st_size < min_size_bytes:
            continue
        if (now - stat.st_mtime) <= max_age_seconds:
            return True
    return False


def format_http_date(dt_utc: datetime) -> str:
    weekday = calendar.day_abbr[dt_utc.weekday()]
    month = calendar.month_abbr[dt_utc.month]
    return f"Date: {weekday}, {dt_utc.day:02d} {month} {dt_utc.year} {dt_utc:%H:%M:%S} GMT"


def format_timezone_date(dt_utc: datetime) -> str:
    weekday = calendar.day_abbr[dt_utc.weekday()]
    month = calendar.month_abbr[dt_utc.month]
    return f"Timezone: {weekday} {month} {dt_utc.day:02d} {dt_utc.year} {dt_utc:%H:%M:%S} GMT+0000"


def reset_checksums(pkt) -> None:
    if pkt.haslayer(IP):
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum
    if pkt.haslayer(IPv6):
        if hasattr(pkt[IPv6], "plen"):
            del pkt[IPv6].plen
    if pkt.haslayer(TCP):
        if hasattr(pkt[TCP], "chksum"):
            del pkt[TCP].chksum
    if pkt.haslayer(UDP):
        if hasattr(pkt[UDP], "len"):
            del pkt[UDP].len
        if hasattr(pkt[UDP], "chksum"):
            del pkt[UDP].chksum


def replace_payload(pkt, replacements) -> bool:
    if not pkt.haslayer(Raw):
        return False

    data = bytes(pkt[Raw].load)
    new = data
    for old_b, new_b in replacements:
        new = new.replace(old_b, new_b)

    if new != data:
        pkt[Raw].load = new
        reset_checksums(pkt)
        return True
    return False


def replace_exact(payload: bytearray, replacements) -> bool:
    changed = False
    for old_b, new_b in replacements:
        new = payload.replace(old_b, new_b)
        if new != payload:
            payload[:] = new
            changed = True
    return changed


def replace_regex(payload: bytearray, pattern: re.Pattern, repl: bytes, label: str) -> bool:
    changed = False

    def _sub(match: re.Match) -> bytes:
        nonlocal changed
        if len(repl) != (match.end() - match.start()):
            raise SystemExit(f"{label} length mismatch for regex replacement.")
        changed = True
        return repl

    new = pattern.sub(_sub, bytes(payload))
    if changed:
        payload[:] = new
    return changed


def flow_key(pkt):
    ip_layer = IP if pkt.haslayer(IP) else IPv6 if pkt.haslayer(IPv6) else None
    if ip_layer is None or not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    return (pkt[ip_layer].src, pkt[ip_layer].dst, tcp.sport, tcp.dport)


def build_tcp_runs(packets, payload_map):
    flows = {}
    for idx, pkt in enumerate(packets):
        if payload_map[idx] is None:
            continue
        if not pkt.haslayer(TCP):
            continue
        key = flow_key(pkt)
        if key is None:
            continue
        tcp = pkt[TCP]
        if not hasattr(tcp, "seq"):
            continue
        payload = bytes(payload_map[idx])
        if not payload:
            continue
        flows.setdefault(key, []).append({"seq": tcp.seq, "payload": payload, "pkt_idx": idx})

    runs_by_flow = {}
    for key, segments in flows.items():
        segments.sort(key=lambda s: s["seq"])
        runs = []
        current = None
        expected = None
        for seg in segments:
            seq = seg["seq"]
            if expected is None or seq > expected:
                current = {"stream": bytearray(), "seg_infos": []}
                runs.append(current)
                expected = seq

            start_offset = 0
            if seq < expected:
                start_offset = expected - seq
            if start_offset >= len(seg["payload"]):
                continue

            payload_part = seg["payload"][start_offset:]
            stream_start = len(current["stream"])
            current["stream"].extend(payload_part)
            current["seg_infos"].append(
                {
                    "pkt_idx": seg["pkt_idx"],
                    "payload_offset": start_offset,
                    "stream_start": stream_start,
                    "length": len(payload_part),
                }
            )
            expected = max(expected, seq + len(seg["payload"]))

        if runs:
            runs_by_flow[key] = runs

    return runs_by_flow


def apply_stream_replacement(seg_infos, start, repl, payload_map, changed_packets):
    remaining = len(repl)
    repl_pos = 0
    idx = 0
    while idx < len(seg_infos) and start >= seg_infos[idx]["stream_start"] + seg_infos[idx]["length"]:
        idx += 1
    while remaining > 0 and idx < len(seg_infos):
        seg = seg_infos[idx]
        seg_start = seg["stream_start"]
        seg_len = seg["length"]
        offset_in_seg = start - seg_start
        if offset_in_seg < 0:
            offset_in_seg = 0
        take = min(remaining, seg_len - offset_in_seg)
        if take <= 0:
            idx += 1
            continue
        pkt_idx = seg["pkt_idx"]
        payload_offset = seg["payload_offset"] + offset_in_seg
        payload_map[pkt_idx][payload_offset : payload_offset + take] = repl[repl_pos : repl_pos + take]
        changed_packets.add(pkt_idx)
        start += take
        repl_pos += take
        remaining -= take
        if start >= seg_start + seg_len:
            idx += 1


def read_port_from_config(config_path: Path) -> Optional[int]:
    if not config_path.is_file():
        return None
    parser = configparser.ConfigParser()
    parser.read(config_path)
    if parser.has_option("default", "pcapoveripport"):
        value = parser.get("default", "pcapoveripport")
        try:
            return int(value)
        except ValueError:
            return None
    return None


def pcap_sort_key(path: Path):
    match = re.search(r"\d+", path.stem)
    if match:
        return (0, int(match.group(0)), path.name)
    return (1, path.name)


def list_pcap_files(pcap_dir: Path) -> List[Path]:
    if not pcap_dir.is_dir():
        return []
    files = [p for p in pcap_dir.iterdir() if p.is_file() and p.suffix.lower() == ".pcap"]
    files.sort(key=pcap_sort_key)
    return files


def send_pcap_over_ip(host: str, port: int, data: bytes, timeout: float = 10.0) -> None:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(data)


def process_pcap_bytes(
    input_path: Path,
    shift_mode: str,
    replacements,
    date_new_b: Optional[bytes],
    tz_new_b: Optional[bytes],
    auto_find: bool,
) -> Tuple[bytes, int, int]:
    with PcapReader(str(input_path)) as r:
        packets = list(r)
        linktype = getattr(r, "linktype", None)

    if not packets:
        raise SystemExit(f"empty pcap: {input_path}")

    times = [float(pkt.time) for pkt in packets]
    min_time = min(times)
    max_time = max(times)

    delta = 0.0
    if shift_mode != "none":
        tgt = target_epoch(shift_mode)
        delta = tgt - times[0]

    if shift_mode == "now":
        now = time.time()
        shifted_max = max_time + delta
        if shifted_max > now:
            delta -= shifted_max - now

    if delta:
        for pkt in packets:
            pkt.time += delta
    logging.info(
        "PCAP %s time range: %.6f..%.6f -> %.6f..%.6f",
        input_path.name,
        min_time,
        max_time,
        min_time + delta,
        max_time + delta,
    )

    payload_map = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload_map.append(bytearray(bytes(pkt[Raw].load)))
        else:
            payload_map.append(None)

    changed_packets = set()

    if replacements:
        for idx, payload in enumerate(payload_map):
            if payload is None:
                continue
            if replace_exact(payload, replacements):
                changed_packets.add(idx)

    if auto_find:
        if date_new_b is not None:
            if len(date_new_b) != len(format_http_date(datetime(2000, 1, 1, tzinfo=timezone.utc)).encode("ascii")):
                raise SystemExit("Date length mismatch for auto-find replacement.")
        if tz_new_b is not None:
            if len(tz_new_b) != len(format_timezone_date(datetime(2000, 1, 1, tzinfo=timezone.utc)).encode("ascii")):
                raise SystemExit("Timezone length mismatch for auto-find replacement.")

        # Non-TCP or packets without seq support: per-packet regex.
        for idx, pkt in enumerate(packets):
            payload = payload_map[idx]
            if payload is None:
                continue
            if pkt.haslayer(TCP):
                continue
            changed = False
            if date_new_b is not None and replace_regex(payload, DATE_RE, date_new_b, "Date"):
                changed = True
            if tz_new_b is not None and replace_regex(payload, TZ_RE, tz_new_b, "Timezone"):
                changed = True
            if changed:
                changed_packets.add(idx)

        # TCP streams: rebuild runs and replace across segments.
        runs_by_flow = build_tcp_runs(packets, payload_map)
        for runs in runs_by_flow.values():
            for run in runs:
                stream_bytes = bytes(run["stream"])
                if date_new_b is not None:
                    for m in DATE_RE.finditer(stream_bytes):
                        apply_stream_replacement(run["seg_infos"], m.start(), date_new_b, payload_map, changed_packets)
                if tz_new_b is not None:
                    for m in TZ_RE.finditer(stream_bytes):
                        apply_stream_replacement(run["seg_infos"], m.start(), tz_new_b, payload_map, changed_packets)

    # Apply payload updates and fix checksums.
    for idx in changed_packets:
        payload = payload_map[idx]
        if payload is None:
            continue
        pkt = packets[idx]
        pkt[Raw].load = bytes(payload)
        reset_checksums(pkt)

    buffer = io.BytesIO()
    writer = PcapWriter(buffer, append=False, sync=True, linktype=linktype)
    for pkt in packets:
        writer.write(pkt)
    writer.flush()
    data = buffer.getvalue()
    writer.close()

    return data, len(packets), len(changed_packets)


def main() -> None:
    setup_logging()
    ap = argparse.ArgumentParser(description="Shift PCAP timestamps and replace Date/Timezone header values.")
    ap.add_argument("--input", help="Input PCAP path")
    ap.add_argument("--output", help="Output PCAP path")
    ap.add_argument(
        "--shift",
        default="none",
        help="Shift timestamps to: none | now | today-00 | epoch:<unix>",
    )
    ap.add_argument("--date-old", default=DEFAULT_DATE_OLD)
    ap.add_argument("--date-new", default=None)
    ap.add_argument("--tz-old", default=DEFAULT_TZ_OLD)
    ap.add_argument("--tz-new", default=None)
    ap.add_argument(
        "--auto-now",
        action="store_true",
        help="Auto-generate date/tz strings from current UTC time when date-new/tz-new are not provided.",
    )
    ap.add_argument(
        "--auto-find",
        action="store_true",
        help="Auto-find Date/Timezone headers via regex and replace them (TCP streams supported).",
    )
    ap.add_argument(
        "--pcap-dir",
        default=str(Path(__file__).resolve().parent / "pcaps"),
        help="Directory containing PCAPs to replay (batch mode).",
    )
    ap.add_argument("--host", default="127.0.0.1", help="PCAP-over-IP destination host")
    ap.add_argument("--port", type=int, default=None, help="PCAP-over-IP destination port")

    args = ap.parse_args()

    if (args.input and not args.output) or (args.output and not args.input):
        raise SystemExit("--input and --output must be used together")

    if args.auto_now:
        now_utc = datetime.now(timezone.utc)
        if args.date_new is None:
            args.date_new = format_http_date(now_utc)
        if args.tz_new is None:
            args.tz_new = format_timezone_date(now_utc)
        args.auto_find = True

    replacements = []
    if args.date_new is not None:
        if len(args.date_new) != len(args.date_old):
            raise SystemExit("Date length mismatch: keep the same length to avoid TCP stream issues.")
        replacements.append((args.date_old.encode("ascii"), args.date_new.encode("ascii")))
    if args.tz_new is not None:
        if len(args.tz_new) != len(args.tz_old):
            raise SystemExit("Timezone length mismatch: keep the same length to avoid TCP stream issues.")
        replacements.append((args.tz_old.encode("ascii"), args.tz_new.encode("ascii")))

    date_new_b = args.date_new.encode("ascii") if args.date_new is not None else None
    tz_new_b = args.tz_new.encode("ascii") if args.tz_new is not None else None

    if args.input and args.output:
        data, packet_count, modified_count = process_pcap_bytes(
            Path(args.input),
            args.shift,
            replacements,
            date_new_b,
            tz_new_b,
            args.auto_find,
        )
        with open(args.output, "wb") as fh:
            fh.write(data)
        print(f"Packets: {packet_count}, modified payloads: {modified_count}")
        return

    activity_dir = Path("/opt/arkime/raw")
    if not has_recent_pcap_activity(activity_dir, max_age_seconds=86400, min_size_bytes=500 * 1024):
        logging.info(
            "No recent PCAP activity in %s (last 24h, >= 500KB). Exiting.",
            activity_dir,
        )
        print("No recent PCAP activity")
        return

    pcap_dir = Path(args.pcap_dir)
    pcap_files = list_pcap_files(pcap_dir)
    if not pcap_files:
        logging.info("No PCAPs found in %s", pcap_dir)
        return

    shift_mode = args.shift
    if shift_mode == "none":
        shift_mode = "now"

    config_path = Path(__file__).resolve().parent / "config.ini"
    port = args.port or read_port_from_config(config_path) or 57012

    logging.info("Replaying %d PCAP(s) from %s to %s:%d", len(pcap_files), pcap_dir, args.host, port)
    for pcap_path in pcap_files:
        data, packet_count, modified_count = process_pcap_bytes(
            pcap_path,
            shift_mode,
            replacements,
            date_new_b,
            tz_new_b,
            args.auto_find,
        )
        try:
            send_pcap_over_ip(args.host, port, data)
            logging.info(
                "Sent %s -> %s:%d (packets: %d, modified: %d)",
                pcap_path.name,
                args.host,
                port,
                packet_count,
                modified_count,
            )
        except OSError as exc:
            logging.error(
                "Failed to send %s to %s:%d: %s",
                pcap_path.name,
                args.host,
                port,
                exc,
            )


if __name__ == "__main__":
    main()
