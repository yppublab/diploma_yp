
import sys
from pathlib import Path

sys.path.insert(0, "/opt/arkime/etc")
import pcap_edit as pe

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw
from scapy.utils import PcapReader, PcapWriter

PCAP_PATH = Path("/opt/arkime/etc/pcaps/2.pcap")
PNG_PATH = Path("/opt/arkime/etc/pcaps/1.png")
BACKUP_PATH = PCAP_PATH.with_suffix(".pcap.bak")


def flow_key(pkt):
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None
    if TCP not in pkt:
        return None
    tcp = pkt[TCP]
    return (ip.src, ip.dst, tcp.sport, tcp.dport)


def parse_headers(block):
    lines = block.split(b"\r\n")
    if not lines:
        return None, {}
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().lower()] = v.strip()
    return lines[0], headers


def parse_chunked_offsets(stream, body_start):
    pos = body_start
    offsets = []
    total = 0
    while True:
        line_end = stream.find(b"\r\n", pos)
        if line_end == -1:
            return None, None
        size_line = stream[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            return None, None
        pos = line_end + 2
        if size == 0:
            return offsets, total
        if pos + size > len(stream):
            return None, None
        offsets.append((pos, size))
        total += size
        pos += size
        if stream[pos:pos + 2] != b"\r\n":
            return None, None
        pos += 2


def iter_http_responses(stream):
    idx = 0
    while True:
        idx = stream.find(b"HTTP/1.", idx)
        if idx == -1:
            return
        hdr_end = stream.find(b"\r\n\r\n", idx)
        if hdr_end == -1:
            return
        status_line, headers = parse_headers(stream[idx:hdr_end])
        body_start = hdr_end + 4
        yield idx, body_start, headers
        idx = body_start


def main():
    if not PCAP_PATH.exists():
        print("pcap not found")
        return 1
    if not PNG_PATH.exists():
        print("png not found")
        return 1

    new_png = PNG_PATH.read_bytes()

    with PcapReader(str(PCAP_PATH)) as r:
        packets = list(r)
        linktype = getattr(r, "linktype", None)

    payload_map = []
    for pkt in packets:
        if pkt.haslayer(Raw):
            payload_map.append(bytearray(bytes(pkt[Raw].load)))
        else:
            payload_map.append(None)

    runs_by_flow = pe.build_tcp_runs(packets, payload_map)

    replaced = 0
    changed_packets = set()

    for runs in runs_by_flow.values():
        for run in runs:
            stream = bytes(run["stream"])
            for _, body_start, headers in iter_http_responses(stream):
                ctype = headers.get(b"content-type", b"").lower()
                if b"image/png" not in ctype:
                    continue

                if b"transfer-encoding" in headers and b"chunked" in headers[b"transfer-encoding"].lower():
                    offsets, total_len = parse_chunked_offsets(stream, body_start)
                    if offsets is None:
                        continue
                    data = new_png
                    if len(data) > total_len:
                        data = data[:total_len]
                    elif len(data) < total_len:
                        data = data + b"\x00" * (total_len - len(data))

                    pos = 0
                    for off, size in offsets:
                        chunk = data[pos:pos + size]
                        pe.apply_stream_replacement(run["seg_infos"], off, chunk, payload_map, changed_packets)
                        pos += size
                    replaced += 1
                elif b"content-length" in headers:
                    try:
                        length = int(headers[b"content-length"].split(b";", 1)[0])
                    except ValueError:
                        continue
                    if body_start + length > len(stream):
                        continue
                    data = new_png
                    if len(data) > length:
                        data = data[:length]
                    elif len(data) < length:
                        data = data + b"\x00" * (length - len(data))
                    pe.apply_stream_replacement(run["seg_infos"], body_start, data, payload_map, changed_packets)
                    replaced += 1

    for idx in changed_packets:
        payload = payload_map[idx]
        if payload is None:
            continue
        pkt = packets[idx]
        pkt[Raw].load = bytes(payload)
        pe.reset_checksums(pkt)

    if replaced == 0:
        print("no png responses replaced")
        return 2

    if not BACKUP_PATH.exists():
        BACKUP_PATH.write_bytes(PCAP_PATH.read_bytes())

    with PcapWriter(str(PCAP_PATH), append=False, sync=True, linktype=linktype) as w:
        for pkt in packets:
            w.write(pkt)

    print(f"replaced {replaced} png response(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
