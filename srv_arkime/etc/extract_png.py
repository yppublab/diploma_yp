
import sys
from pathlib import Path
from scapy.packet import Raw
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP
from scapy.utils import PcapReader

PCAP_PATH = Path('/opt/arkime/etc/pcaps/2.pcap')
OUT_DIR = Path('/opt/arkime/etc/pcaps')


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


def reassemble_runs(segments):
    segments.sort(key=lambda s: s[0])
    runs = []
    current = None
    expected = None
    for seq, payload in segments:
        if not payload:
            continue
        if expected is None or seq > expected:
            current = bytearray()
            runs.append(current)
            expected = seq
        if seq < expected:
            start = expected - seq
            if start >= len(payload):
                continue
            payload = payload[start:]
        current.extend(payload)
        expected = max(expected, seq + len(payload))
    return runs


def parse_headers(header_bytes):
    headers = {}
    lines = header_bytes.split(b"\r\n")
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().lower()] = v.strip()
    return lines[0], headers


def decode_chunked(data):
    pos = 0
    out = bytearray()
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return None
        size_line = data[pos:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            return None
        pos = line_end + 2
        if size == 0:
            return bytes(out)
        if pos + size > len(data):
            return None
        out.extend(data[pos:pos + size])
        pos += size
        if data[pos:pos + 2] != b"\r\n":
            return None
        pos += 2


def extract_images_from_stream(stream):
    images = []
    i = 0
    while True:
        idx = stream.find(b"HTTP/1.", i)
        if idx == -1:
            break
        hdr_end = stream.find(b"\r\n\r\n", idx)
        if hdr_end == -1:
            break
        status_line, headers = parse_headers(stream[idx:hdr_end])
        body_start = hdr_end + 4
        content_type = headers.get(b"content-type", b"").lower()
        if b"image/png" not in content_type:
            i = body_start
            continue
        body = None
        if b"transfer-encoding" in headers and b"chunked" in headers[b"transfer-encoding"].lower():
            body = decode_chunked(stream[body_start:])
        elif b"content-length" in headers:
            try:
                length = int(headers[b"content-length"].split(b";", 1)[0])
            except ValueError:
                length = None
            if length is not None and body_start + length <= len(stream):
                body = stream[body_start:body_start + length]
        if body:
            if body.startswith(b"\x89PNG\r\n\x1a\n"):
                images.append(body)
        i = body_start
    return images


flows = {}
with PcapReader(str(PCAP_PATH)) as r:
    for pkt in r:
        if TCP not in pkt or Raw not in pkt:
            continue
        key = flow_key(pkt)
        if key is None:
            continue
        payload = bytes(pkt[Raw].load)
        if not payload:
            continue
        flows.setdefault(key, []).append((pkt[TCP].seq, payload))

all_images = []
for segments in flows.values():
    for run in reassemble_runs(segments):
        all_images.extend(extract_images_from_stream(bytes(run)))

if not all_images:
    print("No PNG found")
    sys.exit(1)

OUT_DIR.mkdir(parents=True, exist_ok=True)
for idx, img in enumerate(all_images, start=1):
    out_path = OUT_DIR / f"extracted_{idx}.png"
    out_path.write_bytes(img)
    print(f"Saved {out_path} ({len(img)} bytes)")
