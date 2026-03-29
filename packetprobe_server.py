#!/usr/bin/env python3
"""
PacketProbe - PCAP/5View Forensic Analysis Backend
Steganography detection, RFC analysis, image extraction, AI assistant
"""

import os, io, re, math, json, struct, base64, hashlib, socket, collections, urllib.request, urllib.error, subprocess, tempfile, shutil
import threading, time, tempfile, datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

try:
    import dpkt
    DPKT_OK = True
except ImportError:
    DPKT_OK = False

try:
    from PIL import Image, ImageStat
    PIL_OK = True
except ImportError:
    PIL_OK = False

app = Flask(__name__)
CORS(app)

# Use directories relative to wherever this script lives
BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_DIR = BASE_DIR / "uploads"
EXTRACT_DIR = BASE_DIR / "extracted"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

# ─── Utility Functions ────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = collections.Counter(data)
    total = len(data)
    return -sum((c/total)*math.log2(c/total) for c in cnt.values())

def detect_file_magic(data: bytes) -> dict:
    """Detect file type from magic bytes."""
    sigs = [
        (b'\xff\xd8\xff',              'JPEG',  '.jpg'),
        (b'\x89PNG\r\n\x1a\n',         'PNG',   '.png'),
        (b'GIF87a',                     'GIF',   '.gif'),
        (b'GIF89a',                     'GIF',   '.gif'),
        (b'BM',                         'BMP',   '.bmp'),
        (b'RIFF',                       'RIFF',  '.riff'),
        (b'%PDF',                       'PDF',   '.pdf'),
        (b'PK\x03\x04',                'ZIP',   '.zip'),
        (b'\x1f\x8b',                  'GZIP',  '.gz'),
        (b'MZ',                         'EXE',   '.exe'),
        (b'\x7fELF',                   'ELF',   '.elf'),
        (b'OggS',                       'OGG',   '.ogg'),
        (b'fLaC',                       'FLAC',  '.flac'),
        (b'ID3',                        'MP3',   '.mp3'),
        (b'\x00\x00\x00\x18ftyp',      'MP4',   '.mp4'),
        (b'\x00\x00\x01\xba',          'MPEG',  '.mpg'),
        (b'<!DOCTYPE',                  'HTML',  '.html'),
        (b'<html',                      'HTML',  '.html'),
        (b'<?xml',                      'XML',   '.xml'),
    ]
    for magic, ftype, ext in sigs:
        if data[:len(magic)].lower() == magic.lower() or data[:len(magic)] == magic:
            return {'type': ftype, 'ext': ext, 'is_image': ftype in ('JPEG','PNG','GIF','BMP')}
    return {'type': 'UNKNOWN', 'ext': '.bin', 'is_image': False}

def extract_strings(data: bytes, min_len=6) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = rb'[ -~]{%d,}' % min_len
    return [m.group().decode('ascii', errors='replace') for m in re.finditer(pattern, data)]

# EXIF field values that are common benign encoder signatures — do not flag these
BENIGN_EXIF_COMMENTS = {
    'gd-jpeg', 'ijg jpeg', 'adobe photoshop', 'gimp', 'imagemagick',
    'paint.net', 'microsoft', 'apple', 'canon', 'nikon', 'sony',
    'exif_ifd', 'picasa', 'lightroom', 'darktable', 'rawtherapee',
}

# SSH / crypto algorithm name fragments that match @ but are NOT credentials
SSH_ALGO_PATTERNS = re.compile(
    r'@(?:libssh|openssh|ssh\.com|ietf\.org|putty\.projects|bitvise'
    r'|vandyke|ssh-keygen|secsh|openssh\.com|comcast\.net'
    r'|googlecode|tectia|winscp)',
    re.IGNORECASE
)


def check_lsb_stego(image_bytes: bytes) -> dict:
    """LSB steganography detection with size gate and raised threshold.

    Natural JPEG DCT encoding randomises LSBs, so entropy near 1.0 is
    expected for *any* JPEG.  We therefore:
      - Skip images under 5 KB (too few pixels for reliable stats)
      - Require entropy > 0.98 AND pixel count > 500 before flagging
      - Report entropy honestly so analysts can judge for themselves
    """
    if not PIL_OK:
        return {'detected': False, 'reason': 'PIL not available'}
    if len(image_bytes) < 5120:          # < 5 KB — not enough data
        return {'detected': False, 'lsb_entropy': None,
                'reason': 'Image too small for reliable LSB analysis'}
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        pixels = list(img.getdata())
        sample = pixels[:2000]           # larger sample for reliability
        if len(sample) < 500:
            return {'detected': False, 'lsb_entropy': None,
                    'reason': 'Too few pixels for reliable LSB analysis'}
        lsbs = bytes([p[c] & 1 for p in sample for c in range(3)])
        ent = shannon_entropy(lsbs)
        # Raised threshold — JPEG DCT naturally produces high LSB entropy
        # Only flag at 0.98+ AND require the image to be a reasonable size
        suspicious = ent > 0.98 and len(image_bytes) > 10240
        reason = (
            'LSB entropy normal for compressed image' if ent <= 0.95
            else 'LSB entropy elevated — possible stego (verify with zsteg)'
            if suspicious
            else 'LSB entropy high but within expected range for JPEG/compressed image'
        )
        return {
            'detected': suspicious,
            'lsb_entropy': round(ent, 4),
            'reason': reason
        }
    except Exception as e:
        return {'detected': False, 'reason': str(e)}

def check_exif_stego(image_bytes: bytes) -> dict:
    """Check EXIF data for hidden content, skipping known-benign encoder comments."""
    findings = []
    if image_bytes[:2] == b'\xff\xd8':
        i = 2
        while i < len(image_bytes) - 4:
            marker = image_bytes[i:i+2]
            if marker == b'\xff\xe1':  # APP1/EXIF
                length = struct.unpack('>H', image_bytes[i+2:i+4])[0]
                exif_data = image_bytes[i+4:i+2+length]
                strs = extract_strings(exif_data, 8)
                for s in strs:
                    sl = s.lower()
                    # Skip whitelisted benign encoder/software comments
                    if any(benign in sl for benign in BENIGN_EXIF_COMMENTS):
                        continue
                    # Skip SSH/crypto algorithm names containing @
                    if '@' in s and SSH_ALGO_PATTERNS.search(s):
                        continue
                    # Only flag on strong suspicious keywords
                    if any(kw in sl for kw in [
                        'password', 'passwd', 'secret', 'flag{', 'hidden',
                        'eval(', 'base64', 'powershell', 'cmd.exe',
                    ]):
                        findings.append(s[:200])
                break
            if i+3 < len(image_bytes):
                length = struct.unpack('>H', image_bytes[i+2:i+4])[0] if marker[0] == 0xff else 1
                i += max(2, length + 2)
            else:
                break
    return {'suspicious_exif': findings, 'has_hidden_strings': len(findings) > 0}

# ─── PCAP Parser ─────────────────────────────────────────────────────────────

def parse_pcap(filepath: str) -> dict:
    """Parse PCAP file and extract all forensic data."""
    result = {
        'packets': [],
        'stats': {},
        'protocols': collections.Counter(),
        'ip_pairs': [],
        'extracted_images': [],
        'extracted_files': [],
        'stego_findings': [],
        'rfc_violations': [],
        'suspicious_strings': [],
        'http_objects': [],
        'dns_queries': [],
        'credentials': [],
        'raw_payloads': [],
        'errors': []
    }

    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
    except Exception as e:
        result['errors'].append(f'File read error: {e}')
        return result

    # Detect format
    is_pcap = raw[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4')
    is_pcapng = raw[:4] == b'\x0a\x0d\x0d\x0a'
    is_5view = b'5view' in raw[:512].lower() or (not is_pcap and not is_pcapng)

    if is_5view and not is_pcap and not is_pcapng:
        result['stats']['format'] = '5View/Custom'
        result = parse_raw_binary(raw, result)
        return result

    result['stats']['format'] = 'PCAP-NG' if is_pcapng else 'PCAP'

    if not DPKT_OK:
        result['errors'].append('dpkt not available')
        return result

    # Try to use dpkt for PCAP
    if is_pcap:
        try:
            pcap = dpkt.pcap.Reader(io.BytesIO(raw))
            pkt_count = 0
            tcp_streams = {}
            udp_flows = {}

            for ts, buf in pcap:
                pkt_count += 1
                pkt_info = {'num': pkt_count, 'ts': ts, 'len': len(buf), 'layers': []}

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    pkt_info['layers'].append('Ethernet')

                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        pkt_info['layers'].append('IP')
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        pkt_info['src_ip'] = src_ip
                        pkt_info['dst_ip'] = dst_ip
                        pkt_info['proto'] = ip.p

                        # RFC violation checks
                        check_ip_rfc(ip, src_ip, dst_ip, pkt_count, result)

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            pkt_info['layers'].append('TCP')
                            pkt_info['src_port'] = tcp.sport
                            pkt_info['dst_port'] = tcp.dport
                            result['protocols']['TCP'] += 1

                            # Check TCP RFC violations
                            check_tcp_rfc(tcp, pkt_count, result)

                            # Reassemble streams for HTTP/payload analysis
                            stream_key = tuple(sorted([(src_ip, tcp.sport), (dst_ip, tcp.dport)]))
                            if stream_key not in tcp_streams:
                                tcp_streams[stream_key] = b''
                            if tcp.data:
                                tcp_streams[stream_key] += tcp.data

                            # HTTP detection
                            if tcp.dport in (80, 8080, 8000) or tcp.sport in (80, 8080, 8000):
                                result['protocols']['HTTP'] += 1
                                if tcp.data:
                                    parse_http_payload(tcp.data, src_ip, dst_ip, result)

                            # HTTPS
                            if tcp.dport == 443 or tcp.sport == 443:
                                result['protocols']['HTTPS'] += 1

                            # Check for credentials in payloads
                            if tcp.data:
                                scan_for_credentials(tcp.data, src_ip, dst_ip, result)
                                scan_for_suspicious(tcp.data, result)

                        elif isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            pkt_info['layers'].append('UDP')
                            pkt_info['src_port'] = udp.sport
                            pkt_info['dst_port'] = udp.dport
                            result['protocols']['UDP'] += 1

                            # DNS
                            if udp.dport == 53 or udp.sport == 53:
                                result['protocols']['DNS'] += 1
                                try:
                                    dns = dpkt.dns.DNS(udp.data)
                                    for q in dns.qd:
                                        qname = q.name if hasattr(q, 'name') else 'unknown'
                                        result['dns_queries'].append({
                                            'name': qname,
                                            'src': src_ip
                                        })
                                        # DNS tunneling detection
                                        if len(qname) > 50 or qname.count('.') > 5:
                                            result['rfc_violations'].append({
                                                'type': 'DNS_TUNNELING_SUSPECT',
                                                'pkt': pkt_count,
                                                'detail': f'Suspicious DNS query length: {qname[:80]}'
                                            })
                                except Exception:
                                    pass

                            # ICMP tunneling check
                        elif isinstance(ip.data, dpkt.icmp.ICMP):
                            icmp = ip.data
                            pkt_info['layers'].append('ICMP')
                            result['protocols']['ICMP'] += 1
                            if icmp.data and len(icmp.data) > 64:
                                result['rfc_violations'].append({
                                    'type': 'ICMP_TUNNELING_SUSPECT',
                                    'pkt': pkt_count,
                                    'detail': f'Oversized ICMP payload: {len(icmp.data)} bytes'
                                })
                                scan_for_suspicious(bytes(icmp.data), result)

                except Exception:
                    pass

                if pkt_count <= 500:
                    result['packets'].append(pkt_info)

            # Process TCP streams for embedded files
            process_tcp_streams(tcp_streams, result)

            result['stats'].update({
                'total_packets': pkt_count,
                'protocol_breakdown': dict(result['protocols']),
                'total_images_found': len(result['extracted_images']),
                'total_files_found': len(result['extracted_files']),
                'rfc_violations_count': len(result['rfc_violations']),
                'stego_suspects': len(result['stego_findings']),
            })

        except Exception as e:
            result['errors'].append(f'PCAP parse error: {e}')
            # Fall back to raw binary analysis
            result = parse_raw_binary(raw, result)

    else:
        # PCAP-NG or unknown — raw analysis
        result = parse_raw_binary(raw, result)

    return result


def parse_raw_binary(raw: bytes, result: dict) -> dict:
    """Raw binary carving for non-standard formats."""
    result['stats']['format'] = result['stats'].get('format', 'Raw/5View')

    # Carve files from raw binary
    image_sigs = [
        (b'\xff\xd8\xff', b'\xff\xd9', 'JPEG', '.jpg'),
        (b'\x89PNG\r\n\x1a\n', b'IEND\xaeB`\x82', 'PNG', '.png'),
        (b'GIF87a', None, 'GIF', '.gif'),
        (b'GIF89a', None, 'GIF', '.gif'),
    ]

    for sig, end_sig, ftype, ext in image_sigs:
        start = 0
        while True:
            pos = raw.find(sig, start)
            if pos == -1:
                break
            # Try to find end
            if end_sig:
                end_pos = raw.find(end_sig, pos + len(sig))
                if end_pos != -1:
                    img_data = raw[pos:end_pos + len(end_sig)]
                else:
                    img_data = raw[pos:pos + 65536]
            else:
                img_data = raw[pos:pos + 65536]

            if len(img_data) > 100:
                save_extracted_image(img_data, ftype, ext, pos, result)
            start = pos + 1

    # String analysis
    strings = extract_strings(raw, min_len=8)
    for s in strings:
        if any(kw in s.lower() for kw in ['password','passwd','secret','key=','token','Authorization','credential']):
            result['credentials'].append({'string': s[:200], 'context': 'raw_binary'})
        if any(kw in s.lower() for kw in ['http://','https://','ftp://','ssh']):
            result['suspicious_strings'].append(s[:200])

    result['stats']['total_images_found'] = len(result['extracted_images'])
    result['stats']['total_files_found'] = len(result['extracted_files'])
    result['stats']['total_packets'] = len(result['packets'])
    return result


def check_ip_rfc(ip, src_ip, dst_ip, pkt_num, result):
    """Check IP header for RFC 791 violations."""
    # RFC 791: TTL should not be 0
    if ip.ttl == 0:
        result['rfc_violations'].append({
            'type': 'RFC791_TTL_ZERO', 'pkt': pkt_num,
            'detail': f'IP TTL=0 from {src_ip}'
        })
    # Reserved bit set (evil bit RFC 3514)
    if (ip.off >> 15) & 1:
        result['rfc_violations'].append({
            'type': 'RFC3514_EVIL_BIT', 'pkt': pkt_num,
            'detail': f'Evil bit set from {src_ip}'
        })
    # Fragmentation overlap
    if ip.off & 0x1fff and ip.off & 0x2000:
        result['rfc_violations'].append({
            'type': 'RFC791_FRAGMENT_OVERLAP', 'pkt': pkt_num,
            'detail': f'Suspicious fragmentation from {src_ip}'
        })
    # Private IP check (RFC 1918)
    for priv in ['10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.2','172.3']:
        if src_ip.startswith(priv):
            break
    # Loopback used outside loopback context
    if src_ip.startswith('127.') and not dst_ip.startswith('127.'):
        result['rfc_violations'].append({
            'type': 'RFC1122_LOOPBACK_ESCAPE', 'pkt': pkt_num,
            'detail': f'Loopback address {src_ip} used in non-loopback context'
        })


def check_tcp_rfc(tcp, pkt_num, result):
    """Check TCP flags for RFC 793 violations."""
    flags = tcp.flags
    SYN = flags & 0x02
    ACK = flags & 0x10
    FIN = flags & 0x01
    RST = flags & 0x04
    URG = flags & 0x20
    PSH = flags & 0x08

    # XMAS scan: FIN+PSH+URG
    if FIN and PSH and URG:
        result['rfc_violations'].append({
            'type': 'TCP_XMAS_SCAN', 'pkt': pkt_num,
            'detail': 'XMAS scan detected (FIN+PSH+URG)'
        })
    # NULL scan
    if flags == 0:
        result['rfc_violations'].append({
            'type': 'TCP_NULL_SCAN', 'pkt': pkt_num,
            'detail': 'TCP NULL scan (no flags)'
        })
    # SYN+FIN invalid
    if SYN and FIN:
        result['rfc_violations'].append({
            'type': 'RFC793_SYN_FIN', 'pkt': pkt_num,
            'detail': 'Invalid TCP SYN+FIN combination'
        })
    # URG with no urgent pointer
    if URG and tcp.urgptr == 0:
        result['rfc_violations'].append({
            'type': 'RFC793_URG_ZERO_POINTER', 'pkt': pkt_num,
            'detail': 'URG flag set but urgent pointer is 0'
        })


def parse_http_payload(data: bytes, src_ip, dst_ip, result):
    """Parse HTTP payloads for objects and credentials."""
    try:
        text = data.decode('latin-1', errors='replace')
        # Auth headers
        if 'Authorization:' in text or 'authorization:' in text:
            for line in text.split('\n'):
                if 'authorization' in line.lower():
                    result['credentials'].append({'string': line.strip()[:200], 'context': 'HTTP'})
        # HTTP basic auth in URL
        if re.search(r'https?://[^:]+:[^@]+@', text):
            m = re.findall(r'https?://([^:]+):([^@]+)@', text)
            for u, p in m:
                result['credentials'].append({'string': f'HTTP URL Credentials: {u}:{p}', 'context': 'HTTP_URL'})

        # Look for image content types
        if 'Content-Type: image' in text or 'content-type: image' in text:
            # Find body after headers
            if b'\r\n\r\n' in data:
                _, body = data.split(b'\r\n\r\n', 1)
                if body:
                    finfo = detect_file_magic(body)
                    if finfo['is_image']:
                        save_extracted_image(body, finfo['type'], finfo['ext'], 0, result)

        # POST data
        if text.startswith('POST') and b'\r\n\r\n' in data:
            _, body = data.split(b'\r\n\r\n', 1)
            body_text = body.decode('latin-1', errors='replace')
            if any(kw in body_text.lower() for kw in ['password','passwd','secret','token','apikey']):
                result['credentials'].append({'string': body_text[:300], 'context': 'HTTP_POST'})

        # HTTP objects
        if text.startswith(('GET ','POST ','HTTP/','PUT ','DELETE ')):
            first_line = text.split('\n')[0].strip()
            result['http_objects'].append({'method_or_status': first_line[:200], 'src': src_ip, 'dst': dst_ip})

    except Exception:
        pass


# Password-field values that are almost certainly false positives
FP_PASSWORD_PATTERNS = re.compile(
    r'^(?:null|undefined|none|true|false|function\(|function |var |'
    r'return |this\.|document\.|window\.|0x[0-9a-f]+|[\[\]{}<>]).*',
    re.IGNORECASE
)

def scan_for_credentials(data: bytes, src_ip, dst_ip, result):
    """Scan payload for credential patterns, filtering known false-positive patterns."""
    text = data.decode('latin-1', errors='replace')

    # Non-email credential patterns
    cred_patterns = [
        (r'(?i)password[=:\s]+([^\s&\r\n]{4,64})', 'password'),
        (r'(?i)passwd[=:\s]+([^\s&\r\n]{4,64})', 'passwd'),
        (r'(?i)api[_-]?key[=:\s]+([^\s&\r\n]{8,64})', 'api_key'),
        (r'(?i)secret[=:\s]+([^\s&\r\n]{4,64})', 'secret'),
        (r'(?i)token[=:\s]+([^\s&\r\n]{8,128})', 'token'),
    ]
    for pattern, ptype in cred_patterns:
        matches = re.findall(pattern, text)
        for m in matches[:3]:
            val = str(m).strip()
            # Drop obvious JS/code false positives
            if FP_PASSWORD_PATTERNS.match(val):
                continue
            if len(val) < 4:
                continue
            result['credentials'].append({'type': ptype, 'string': val[:200], 'src': src_ip})

    # Email pattern — separate pass with SSH algo exclusion
    email_re = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    for m in email_re.findall(text)[:5]:
        # Exclude SSH/IETF algorithm names (contain @ but are not addresses)
        if SSH_ALGO_PATTERNS.search(m):
            continue
        # Must have a plausible TLD (not .org crypto tokens like openssh.com/curve...)
        # and must not be all-lowercase-hyphenated-algo-style
        if re.match(r'^[a-z0-9_-]+@[a-z0-9_.-]+$', m) and len(m.split('@')[0]) > 3:
            # Extra check: skip anything that looks like an algo identifier
            local = m.split('@')[0]
            if re.search(r'(sha|aes|gcm|cbc|hmac|rsa|dsa|ecdsa|kex|chacha|poly)', local, re.I):
                continue
            result['credentials'].append({'type': 'email', 'string': m[:200], 'src': src_ip})


def scan_for_suspicious(data: bytes, result):
    """Scan for suspicious content."""
    text = data.decode('latin-1', errors='replace')
    suspicious_kw = [
        'eval(', 'exec(', 'base64', 'powershell', 'cmd.exe', '/bin/sh', '/bin/bash',
        'wget ', 'curl ', 'nc -', 'netcat', 'meterpreter', 'mimikatz', 'nmap',
        'sqlmap', 'union select', 'drop table', '<script', 'javascript:', 'vbscript:',
        '\\x00', '\x00\x00\x00\x00',
    ]
    for kw in suspicious_kw:
        if kw.lower() in text.lower():
            ctx = text[max(0, text.lower().find(kw.lower())-20):text.lower().find(kw.lower())+60]
            if ctx not in [s for s in result['suspicious_strings']]:
                result['suspicious_strings'].append(ctx[:200])


def process_tcp_streams(streams: dict, result: dict):
    """Carve files from reassembled TCP streams."""
    for stream_key, data in streams.items():
        if len(data) < 50:
            continue
        # Carve embedded images/files
        for sig, ftype, ext in [
            (b'\xff\xd8\xff', 'JPEG', '.jpg'),
            (b'\x89PNG\r\n\x1a\n', 'PNG', '.png'),
            (b'GIF89a', 'GIF', '.gif'),
            (b'GIF87a', 'GIF', '.gif'),
            (b'%PDF', 'PDF', '.pdf'),
            (b'PK\x03\x04', 'ZIP', '.zip'),
        ]:
            pos = 0
            while True:
                idx = data.find(sig, pos)
                if idx == -1:
                    break
                chunk = data[idx:idx+512000]  # max 500KB
                if ftype in ('JPEG', 'PNG', 'GIF'):
                    save_extracted_image(chunk, ftype, ext, idx, result)
                else:
                    save_extracted_file(chunk, ftype, ext, idx, result)
                pos = idx + 1
                if pos > len(data) - len(sig):
                    break


def save_extracted_image(data: bytes, ftype: str, ext: str, offset: int, result: dict):
    """Save extracted image and run stego analysis."""
    if len(data) < 100:
        return
    h = hashlib.md5(data[:1024]).hexdigest()[:8]
    # Deduplicate
    existing = [x['hash'] for x in result['extracted_images']]
    if h in existing:
        return

    fname = f"img_{h}{ext}"
    fpath = EXTRACT_DIR / fname
    try:
        with open(fpath, 'wb') as f:
            f.write(data[:2097152])  # cap at 2MB
    except Exception:
        return

    # Stego analysis
    lsb = check_lsb_stego(data[:2097152])
    exif = check_exif_stego(data[:2097152])
    ent = shannon_entropy(data[:4096])

    img_info = {
        'hash': h,
        'filename': fname,
        'size': len(data),
        'type': ftype,
        'offset': offset,
        'entropy': round(ent, 4),
        'lsb_stego': lsb,
        'exif_analysis': exif,
        'b64_preview': None
    }

    # Generate tiny preview
    try:
        if PIL_OK and ftype in ('JPEG', 'PNG', 'GIF', 'BMP'):
            img = Image.open(io.BytesIO(data[:2097152]))
            img.thumbnail((120, 120))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            img_info['b64_preview'] = base64.b64encode(buf.getvalue()).decode()
            img_info['dimensions'] = f"{img.width}x{img.height}"
    except Exception:
        pass

    if lsb.get('detected') or exif.get('has_hidden_strings'):
        result['stego_findings'].append({
            'file': fname,
            'type': 'IMAGE_STEGO',
            'details': lsb,
            'exif': exif
        })

    result['extracted_images'].append(img_info)


def save_extracted_file(data: bytes, ftype: str, ext: str, offset: int, result: dict):
    """Save extracted non-image file."""
    if len(data) < 50:
        return
    h = hashlib.md5(data[:1024]).hexdigest()[:8]
    existing = [x['hash'] for x in result['extracted_files']]
    if h in existing:
        return

    fname = f"file_{h}{ext}"
    fpath = EXTRACT_DIR / fname
    try:
        with open(fpath, 'wb') as f:
            f.write(data[:1048576])
    except Exception:
        return

    result['extracted_files'].append({
        'hash': h,
        'filename': fname,
        'size': len(data),
        'type': ftype,
        'offset': offset,
        'entropy': round(shannon_entropy(data[:4096]), 4)
    })


# ─── Deep Extraction Engine ──────────────────────────────────────────────────

def run_cmd(cmd, timeout=30):
    """Run a shell command safely, return (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', 'timeout', -1
    except FileNotFoundError:
        return '', f'{cmd[0]} not found', -1
    except Exception as e:
        return '', str(e), -1


def lsb_extract_python(image_bytes: bytes) -> dict:
    """Pure-Python LSB extraction across all bit planes — zsteg equivalent."""
    try:
        import numpy as np
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        arr = np.array(img)
        results = {}

        for channel_idx, channel_name in enumerate(['R', 'G', 'B']):
            for bit in range(8):
                bits = ((arr[:, :, channel_idx] >> bit) & 1).flatten()
                # Pack bits into bytes
                n = (len(bits) // 8) * 8
                bits = bits[:n]
                byte_arr = np.packbits(bits)
                raw = bytes(byte_arr[:2048])  # first 2KB of extracted data

                # Check for printable text
                printable = re.findall(rb'[ -~]{6,}', raw)
                strings_found = [s.decode('ascii', errors='replace') for s in printable]

                # Check for file magic
                magic = detect_file_magic(raw)

                if strings_found or magic['type'] != 'UNKNOWN':
                    key = f"{channel_name}_bit{bit}"
                    results[key] = {
                        'strings': strings_found[:10],
                        'file_magic': magic['type'] if magic['type'] != 'UNKNOWN' else None,
                        'entropy': round(shannon_entropy(raw), 4),
                        'raw_b64': base64.b64encode(raw[:256]).decode() if magic['type'] != 'UNKNOWN' else None
                    }

        return {'method': 'python_lsb', 'findings': results, 'error': None}
    except Exception as e:
        return {'method': 'python_lsb', 'findings': {}, 'error': str(e)}


def run_binwalk(filepath: str) -> dict:
    """Run binwalk signature scan on a file."""
    stdout, stderr, rc = run_cmd(['binwalk', '--signature', '--quiet', filepath])
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith('DECIMAL') and not line.startswith('---') and line[0].isdigit():
            parts = line.split(None, 2)
            if len(parts) >= 3:
                findings.append({
                    'offset_dec': parts[0],
                    'offset_hex': parts[1],
                    'description': parts[2]
                })
    return {'tool': 'binwalk', 'findings': findings, 'raw': stdout[:2000], 'error': stderr[:200] if rc != 0 else None}


def run_exiftool(filepath: str) -> dict:
    """Run exiftool on a file and return all metadata."""
    stdout, stderr, rc = run_cmd(['exiftool', '-json', filepath])
    try:
        meta = json.loads(stdout)
        if meta:
            suspicious = {}
            for k, v in meta[0].items():
                val_str = str(v).lower()
                key_lower = k.lower()
                # Skip fields whose values are whitelisted encoder signatures
                if any(benign in val_str for benign in BENIGN_EXIF_COMMENTS):
                    continue
                # Flag strong suspicious keyword in value
                if any(kw in val_str for kw in ['password', 'secret', 'flag{', 'hidden', 'cmd', 'eval(']):
                    suspicious[k] = str(v)
                    continue
                # Flag metadata comment/description fields only if non-trivial
                if any(kw in key_lower for kw in ['comment', 'usercomment', 'artist', 'copyright']):
                    if str(v).strip() and len(str(v)) > 4:
                        suspicious[k] = str(v)
            return {'tool': 'exiftool', 'metadata': meta[0], 'suspicious_fields': suspicious, 'error': None}
    except Exception:
        pass
    return {'tool': 'exiftool', 'metadata': {}, 'suspicious_fields': {}, 'raw': stdout[:1000], 'error': stderr[:200]}


def run_strings_deep(filepath: str) -> dict:
    """Run strings with multiple encodings."""
    results = {}
    for enc, flag in [('ascii', '-a'), ('unicode', '-el')]:
        stdout, _, rc = run_cmd(['strings', '-n', '8', flag, filepath])
        found = [s.strip() for s in stdout.splitlines() if s.strip()]
        # Filter for interesting strings
        interesting = []
        for s in found:
            sl = s.lower()
            if any(kw in sl for kw in [
                'password', 'passwd', 'secret', 'key=', 'token', 'flag{', 'ctf',
                'http://', 'https://', 'ftp://', '.onion', 'base64', 'eval(',
                'powershell', '/bin/sh', 'cmd.exe', 'wget', 'curl'
            ]):
                interesting.append(s[:200])
        results[enc] = {'total': len(found), 'interesting': interesting[:20]}
    return {'tool': 'strings', 'results': results}


def run_steghide_info(filepath: str) -> dict:
    """Run steghide info and distinguish capacity-found from payload-extracted.

    steghide with an empty passphrase (-p '') will:
      - Report the file format and *theoretical* capacity even with no payload
      - Only confirm payload if it can actually extract data
    We therefore distinguish three states:
      - payload_extracted : data was actually recovered (strong evidence)
      - capacity_only     : format recognised, capacity reported, no extraction
                            (weak — normal for any JPEG/BMP)
      - not_detected      : steghide could not process the file
    """
    stdout, stderr, rc = run_cmd(['steghide', 'info', '-p', '', filepath], timeout=10)
    combined = stdout + stderr
    combined_lower = combined.lower()

    # Strong signal: steghide actually extracted data
    payload_extracted = (
        'extracting secret data' in combined_lower
        or ('wrote extracted data' in combined_lower)
    )
    # Weak signal: file is a recognised format but nothing extracted
    capacity_only = (
        not payload_extracted
        and ('format' in combined_lower or 'capacity' in combined_lower)
        and 'could not extract' not in combined_lower
        and 'premature end' not in combined_lower
    )
    # Explicitly truncated/malformed
    truncated = 'premature end' in combined_lower or 'unexpected end' in combined_lower

    if payload_extracted:
        label = 'PAYLOAD EXTRACTED — strong steganography evidence'
    elif truncated:
        label = 'File truncated/malformed — steghide could not complete'
    elif capacity_only:
        label = 'Capacity reported only — no payload recovered (normal for any JPEG/BMP)'
    else:
        label = 'No steganographic payload detected'

    return {
        'tool': 'steghide',
        'detected': payload_extracted,          # only True when data is actually recovered
        'capacity_only': capacity_only,
        'truncated': truncated,
        'label': label,
        'output': combined[:500]
    }


def deep_extract_image(filename: str) -> dict:
    """Run full extraction suite on a single extracted image."""
    fpath = EXTRACT_DIR / filename
    if not fpath.exists():
        return {'error': 'File not found'}

    with open(str(fpath), 'rb') as f:
        image_bytes = f.read()

    results = {
        'filename': filename,
        'size': len(image_bytes),
        'entropy': round(shannon_entropy(image_bytes), 4),
    }

    # Run all tools
    results['lsb'] = lsb_extract_python(image_bytes)
    results['binwalk'] = run_binwalk(str(fpath))
    results['exiftool'] = run_exiftool(str(fpath))
    results['strings'] = run_strings_deep(str(fpath))

    # Only run steghide on JPEG/BMP (it doesn't support PNG)
    if filename.lower().endswith(('.jpg', '.jpeg', '.bmp')):
        results['steghide'] = run_steghide_info(str(fpath))

    # ── Severity scoring ────────────────────────────────────────────────────
    # Rule: HIGH requires 2+ *independent* strong signals.
    # Steghide capacity-only and common EXIF comments do NOT count as strong.
    strong_flags = []   # count toward HIGH
    weak_flags   = []   # informational only

    if results['lsb']['findings']:
        strong_flags.append(f"LSB: {len(results['lsb']['findings'])} suspicious bit-plane(s)")

    if results['binwalk']['findings']:
        strong_flags.append(f"Binwalk: {len(results['binwalk']['findings'])} embedded signature(s)")

    exif_sus = results['exiftool'].get('suspicious_fields', {})
    # Filter out whitelisted encoder comments from exiftool findings too
    real_exif = {
        k: v for k, v in exif_sus.items()
        if not any(benign in str(v).lower() for benign in BENIGN_EXIF_COMMENTS)
    }
    if real_exif:
        strong_flags.append(f"EXIF: {len(real_exif)} suspicious field(s)")
    elif exif_sus:
        weak_flags.append(f"EXIF: {len(exif_sus)} field(s) (common encoder metadata)")

    for enc, d in results['strings']['results'].items():
        if d['interesting']:
            strong_flags.append(f"Strings ({enc}): {len(d['interesting'])} hits")

    sg = results.get('steghide', {})
    if sg.get('detected'):                        # actual payload extracted
        strong_flags.append("Steghide: PAYLOAD EXTRACTED")
    elif sg.get('truncated'):
        weak_flags.append("Steghide: file truncated/malformed")
    elif sg.get('capacity_only'):
        weak_flags.append("Steghide: capacity reported only (no payload — normal for JPEG/BMP)")

    all_flags = strong_flags + weak_flags

    # HIGH = 2+ strong independent signals
    # MEDIUM = 1 strong signal OR 2+ weak signals
    # LOW = weak signals only or nothing
    if len(strong_flags) >= 2:
        severity = 'HIGH'
    elif len(strong_flags) == 1:
        severity = 'MEDIUM'
    elif len(weak_flags) >= 2:
        severity = 'LOW-MEDIUM'
    else:
        severity = 'LOW'

    results['severity'] = severity
    results['flags'] = all_flags
    results['strong_flags'] = strong_flags
    results['weak_flags'] = weak_flags
    return results


# ─── Flask Routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the frontend HTML."""
    html_path = BASE_DIR / 'packetprobe.html'
    if html_path.exists():
        return send_file(str(html_path))
    return (
        '<h2>PacketProbe backend is running.</h2>'
        '<p>Place <code>packetprobe.html</code> in the same folder as this script, '
        'then visit <a href="/">http://localhost:7734</a> — '
        'or just open the HTML file directly in your browser.</p>',
        200
    )


@app.route('/api/chat', methods=['POST'])
def chat_proxy():
    """Proxy Claude API calls server-side to avoid browser CORS restrictions."""
    body = request.get_json()
    if not body:
        return jsonify({'error': 'No body provided'}), 400

    api_key = body.pop('api_key', None)
    if not api_key:
        return jsonify({'error': 'No api_key provided in request body'}), 400

    payload = json.dumps(body).encode('utf-8')
    req = urllib.request.Request(
        'https://api.anthropic.com/v1/messages',
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
        },
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return jsonify(json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        return jsonify({'error': error_body}), e.code
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'dpkt': DPKT_OK, 'pil': PIL_OK})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint — accepts multipart FormData OR base64 JSON."""
    # Accept base64 JSON body (postMessage-safe, used by artifact sandbox)
    if request.is_json:
        body = request.get_json()
        if not body or 'data' not in body:
            return jsonify({'error': 'No data provided'}), 400
        fname = (body.get('filename') or 'capture.pcap').replace('/', '_').replace('\\', '_')
        try:
            file_bytes = base64.b64decode(body['data'])
        except Exception as e:
            return jsonify({'error': f'base64 decode error: {e}'}), 400
        fpath = UPLOAD_DIR / fname
        with open(str(fpath), 'wb') as fout:
            fout.write(file_bytes)

    # Accept multipart FormData (direct browser use)
    elif 'file' in request.files:
        f = request.files['file']
        if not f.filename:
            return jsonify({'error': 'Empty filename'}), 400
        fname = f.filename.replace('/', '_').replace('\\', '_')
        fpath = UPLOAD_DIR / fname
        f.save(str(fpath))

    else:
        return jsonify({'error': 'No file provided — send multipart form or base64 JSON'}), 400

    try:
        result = parse_pcap(str(fpath))
        result['filename'] = fname
        result['analyzed_at'] = datetime.datetime.now().isoformat()

        # Deduplicate some lists
        result['suspicious_strings'] = list(dict.fromkeys(result['suspicious_strings']))[:50]
        result['credentials'] = result['credentials'][:30]
        result['rfc_violations'] = result['rfc_violations'][:100]
        result['http_objects'] = result['http_objects'][:50]
        result['dns_queries'] = result['dns_queries'][:100]

        # Serialize protocols counter
        result['protocols'] = dict(result['protocols'])

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'filename': fname}), 500


@app.route('/api/extract/<filename>', methods=['GET'])
def extract_image(filename):
    """Deep stego extraction on a single image."""
    safe = filename.replace('/', '').replace('\\', '')
    result = deep_extract_image(safe)
    return jsonify(result)


@app.route('/api/extract_all', methods=['GET'])
def extract_all():
    """Run deep extraction on ALL extracted images (no cap)."""
    images = sorted(EXTRACT_DIR.glob('img_*'))
    results = []
    for img in images:
        results.append(deep_extract_image(img.name))
    return jsonify({'results': results, 'total': len(results), 'processed': len(images)})


@app.route('/api/files')
def list_files():
    """Return every file currently in the extracted directory with metadata."""
    files = []
    for f in sorted(EXTRACT_DIR.iterdir()):
        if f.is_file():
            files.append({
                'filename': f.name,
                'size': f.stat().st_size,
                'url': f'/api/image/{f.name}',
                'download_url': f'/api/download/{f.name}',
                'is_image': f.suffix.lower() in ('.jpg','.jpeg','.png','.gif','.bmp'),
            })
    return jsonify({'files': files, 'total': len(files), 'directory': str(EXTRACT_DIR)})


@app.route('/api/clear', methods=['POST'])
def clear_extractions():
    """Manually wipe the extracted directory."""
    removed = 0
    for f in EXTRACT_DIR.glob('*'):
        try:
            f.unlink()
            removed += 1
        except Exception:
            pass
    return jsonify({'cleared': removed})


@app.route('/api/image/<filename>')
def get_image(filename):
    """Serve extracted image."""
    safe = filename.replace('/', '').replace('\\', '')
    fpath = EXTRACT_DIR / safe
    if fpath.exists():
        return send_file(str(fpath))
    return jsonify({'error': 'not found'}), 404


@app.route('/api/download/<filename>')
def download_file(filename):
    """Download extracted file."""
    safe = filename.replace('/', '').replace('\\', '')
    fpath = EXTRACT_DIR / safe
    if fpath.exists():
        return send_file(str(fpath), as_attachment=True)
    return jsonify({'error': 'not found'}), 404


if __name__ == '__main__':
    print("PacketProbe backend starting on :7734")
    app.run(host='0.0.0.0', port=7734, debug=False)
