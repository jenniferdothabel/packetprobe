#!/usr/bin/env python3
"""
PacketProbe - PCAP/5View Forensic Analysis Backend
Steganography detection, RFC analysis, image extraction, AI assistant
"""

import os, io, re, math, json, struct, base64, hashlib, socket, collections
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

def check_lsb_stego(image_bytes: bytes) -> dict:
    """Basic LSB steganography detection in images."""
    if not PIL_OK:
        return {'detected': False, 'reason': 'PIL not available'}
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        pixels = list(img.getdata())
        lsbs = bytes([p[c] & 1 for p in pixels[:1000] for c in range(3)])
        ent = shannon_entropy(lsbs)
        # High entropy in LSBs suggests random/hidden data
        suspicious = ent > 0.95
        return {
            'detected': suspicious,
            'lsb_entropy': round(ent, 4),
            'reason': 'High LSB entropy suggests embedded data' if suspicious else 'LSB entropy normal'
        }
    except Exception as e:
        return {'detected': False, 'reason': str(e)}

def check_exif_stego(image_bytes: bytes) -> dict:
    """Check EXIF data for hidden content."""
    findings = []
    # Look for EXIF marker in JPEG
    if image_bytes[:2] == b'\xff\xd8':
        i = 2
        while i < len(image_bytes) - 4:
            marker = image_bytes[i:i+2]
            if marker == b'\xff\xe1':  # APP1/EXIF
                length = struct.unpack('>H', image_bytes[i+2:i+4])[0]
                exif_data = image_bytes[i+4:i+2+length]
                strs = extract_strings(exif_data, 8)
                for s in strs:
                    if any(kw in s.lower() for kw in ['http','password','secret','key','flag','hidden']):
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


def scan_for_credentials(data: bytes, src_ip, dst_ip, result):
    """Scan payload for credential patterns."""
    text = data.decode('latin-1', errors='replace')
    patterns = [
        (r'(?i)password[=:\s]+([^\s&\r\n]{4,64})', 'password'),
        (r'(?i)passwd[=:\s]+([^\s&\r\n]{4,64})', 'passwd'),
        (r'(?i)api[_-]?key[=:\s]+([^\s&\r\n]{8,64})', 'api_key'),
        (r'(?i)secret[=:\s]+([^\s&\r\n]{4,64})', 'secret'),
        (r'(?i)token[=:\s]+([^\s&\r\n]{8,128})', 'token'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email'),
    ]
    for pattern, ptype in patterns:
        matches = re.findall(pattern, text)
        for m in matches[:3]:
            result['credentials'].append({'type': ptype, 'string': str(m)[:200], 'src': src_ip})


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


# ─── Flask Routes ─────────────────────────────────────────────────────────────

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'dpkt': DPKT_OK, 'pil': PIL_OK})


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint — accepts multipart FormData OR base64 JSON."""
    # Clear old extractions
    for old_file in EXTRACT_DIR.glob('*'):
        try:
            old_file.unlink()
        except Exception:
            pass

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
