# 📡 PacketProbe

**PCAP / 5View Forensic Analyzer with AI Assistant**

PacketProbe is a self-hosted network forensics tool that analyzes PCAP, PCAP-NG, and raw binary capture files. It extracts embedded images, detects RFC violations, scans for steganography, identifies cleartext credentials, and provides an interactive Claude AI assistant to help interpret findings.

![PacketProbe](https://img.shields.io/badge/forensics-PCAP%20analyzer-00d4ff?style=for-the-badge&logo=wireshark)
![Python](https://img.shields.io/badge/python-3.8+-00ff9f?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/license-MIT-bd00ff?style=for-the-badge)

---

## Features

- **PCAP / PCAP-NG / 5View / Raw Binary** parsing
- **RFC Violation Detection**
  - TCP XMAS scan, NULL scan, SYN+FIN (RFC 793)
  - IP TTL=0, evil bit (RFC 3514), fragment overlap (RFC 791)
  - Loopback address escape (RFC 1122)
  - URG flag with zero pointer
- **Steganography Detection**
  - LSB (Least Significant Bit) entropy analysis
  - EXIF metadata anomaly scanning
- **Image Extraction** — carves JPEG, PNG, GIF, BMP from TCP streams and raw binary
- **DNS Tunneling Detection** — flags oversized query names (dnscat2, iodine patterns)
- **ICMP Tunneling Detection** — oversized payload analysis
- **Credential Scanning** — passwords, API keys, tokens in HTTP payloads and POST bodies
- **TCP Stream Reassembly** — for HTTP object and file extraction
- **Interactive AI Assistant** — powered by Claude, auto-briefed from analysis results
- **Detailed Report** — risk rating, key findings, and prioritized recommendations

---

## Project Structure

```
packetprobe/
├── packetprobe.html          # Frontend UI (single-file, open in browser)
├── packetprobe_server.py     # Flask backend — all analysis logic
└── README.md
```

---

## Requirements

- Python 3.8+
- pip packages: `flask`, `flask-cors`, `dpkt`, `pillow`

```bash
pip install flask flask-cors dpkt pillow
```

---

## Setup & Running

### 1. Clone the repo

```bash
git clone https://github.com/jenniferdothabel/packetprobe.git
cd packetprobe
```

### 2. Install dependencies

```bash
pip install flask flask-cors dpkt pillow
```

### 3. Start the backend server

```bash
python3 packetprobe_server.py
```

The server starts on **http://localhost:7734**. You should see:

```
PacketProbe backend starting on :7734
```

### 4. Open the frontend

Open `packetprobe.html` directly in your browser:

```bash
# macOS
open packetprobe.html

# Linux
xdg-open packetprobe.html

# Windows
start packetprobe.html
```

The status bar in the top right will confirm **BACKEND READY** when the frontend connects successfully.

---

## Usage

1. **Drop a capture file** onto the upload zone or click to browse
   - Supported: `.pcap`, `.pcapng`, `.cap`, `.5vw`, `.bin`, raw binary
2. Click **⚡ ANALYZE**
3. Browse results across tabs:
   - **Overview** — packet stats, protocol breakdown, DNS queries
   - **RFC Violations** — detailed violation list with RFC citations
   - **Steganography** — LSB entropy and EXIF anomaly findings
   - **Images** — extracted images with stego indicators, click to inspect
   - **Credentials** — cleartext credential exposures
   - **Packets** — raw packet list with layer breakdown
   - **Report** — executive summary, risk rating, and recommendations
4. Use the **AI Assistant** panel to ask questions about the findings

### AI Assistant Setup

The AI assistant uses the Claude API. To enable it, the frontend calls the Anthropic API directly from your browser. You'll need an API key from [console.anthropic.com](https://console.anthropic.com).

By default the app uses `claude-sonnet-4-20250514`. To configure your key, open `packetprobe.html` and locate the `askAI` function — add your key to the fetch headers:

```js
headers: {
  'Content-Type': 'application/json',
  'x-api-key': 'YOUR_ANTHROPIC_API_KEY',
  'anthropic-version': '2023-06-01'
}
```

---

## API Endpoints

The backend exposes a simple REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check — returns dpkt/PIL status |
| `POST` | `/api/analyze` | Analyze a capture file |
| `GET` | `/api/image/<filename>` | Serve an extracted image |
| `GET` | `/api/download/<filename>` | Download an extracted file |

### `/api/analyze` — two accepted formats

**Multipart FormData** (direct browser / curl):
```bash
curl -X POST http://localhost:7734/api/analyze \
  -F "file=@capture.pcap"
```

**Base64 JSON** (artifact/sandboxed environments):
```bash
curl -X POST http://localhost:7734/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"filename":"capture.pcap","data":"<base64>"}'
```

---

## Steganography Detection Details

PacketProbe uses two methods to flag images for steganographic content:

**LSB Entropy Analysis** — extracts the least significant bit of each RGB channel across the first 1,000 pixels and computes Shannon entropy. Natural images have patterned LSBs (entropy < 0.95). Random/embedded data produces near-maximum entropy (≥ 0.95), which flags the image as a suspect.

**EXIF Anomaly Scanning** — parses JPEG APP1 markers and extracts printable strings. Strings containing keywords like `password`, `secret`, `key`, `flag`, `http`, or `hidden` are reported.

For confirmed steganography investigation, run flagged images through:
- [`zsteg`](https://github.com/zed-0xff/zsteg) — PNG/BMP LSB detection
- [`stegdetect`](http://www.outguess.org/) — JPEG stego tool detection  
- [`binwalk`](https://github.com/ReFirmLabs/binwalk) — embedded file carving
- [`StegExpose`](https://github.com/b3dk7/StegExpose) — statistical stego detection

---

## RFC Violations Reference

| Violation Type | RFC | Description |
|---|---|---|
| `TCP_XMAS_SCAN` | RFC 793 | FIN+PSH+URG flags set simultaneously |
| `TCP_NULL_SCAN` | RFC 793 | No TCP flags set |
| `RFC793_SYN_FIN` | RFC 793 | SYN and FIN set simultaneously |
| `RFC793_URG_ZERO_POINTER` | RFC 793 | URG flag with zero urgent pointer |
| `RFC791_TTL_ZERO` | RFC 791 | IP TTL = 0 at origin |
| `RFC791_FRAGMENT_OVERLAP` | RFC 791 | Overlapping IP fragments |
| `RFC3514_EVIL_BIT` | RFC 3514 | Reserved IP header bit set |
| `RFC1122_LOOPBACK_ESCAPE` | RFC 1122 | Loopback address used externally |
| `DNS_TUNNELING_SUSPECT` | RFC 1035 | Excessively long DNS query name |
| `ICMP_TUNNELING_SUSPECT` | RFC 792 | Oversized ICMP payload (>64 bytes) |

---

## Security Notes

- PacketProbe is intended for **authorized forensic analysis only**
- Run only against capture files you own or have explicit permission to analyze
- The backend stores uploaded files and extracted artifacts in local temp directories
- No data is sent anywhere except the Anthropic API (AI assistant only)
- Revoke your Anthropic API key if you embed it in the HTML and share the file

---

## Deploying to Namecheap Shared Hosting (cPanel)

PacketProbe supports deployment to Namecheap shared hosting via cPanel's built-in Python App feature. No VPS required.

### Step 1 — Create a Python App in cPanel

1. Log in to cPanel → **Software** → **Setup Python App**
2. Click **Create Application**
3. Set:
   - **Python version:** 3.10 or higher
   - **Application root:** `packetprobe` (or any folder name)
   - **Application URL:** select your domain or subdomain (e.g. `pcap.yourdomain.com`)
   - **Application startup file:** `passenger_wsgi.py`
   - **Application entry point:** `application`
4. Click **Create**

### Step 2 — Upload the files

Upload all files from this repo into the Application root folder via **File Manager** or **Git Version Control** in cPanel:

```
packetprobe/
├── packetprobe_server.py
├── packetprobe.html
├── passenger_wsgi.py
├── requirements.txt
└── .htaccess
```

### Step 3 — Install dependencies

1. Back in **Setup Python App**, find your app and click **Edit**
2. In **Configuration files**, enter `requirements.txt` and click **Add**
3. Click **Run Pip Install**

Or via SSH:
```bash
source /home/YOUR_CPANEL_USER/virtualenv/packetprobe/3.10/bin/activate
pip install -r requirements.txt
```

### Step 4 — Restart and test

1. Click **Restart** in the Python App panel
2. Visit your application URL — you should see PacketProbe load

### Troubleshooting

If you see a blank page or error, enable friendly errors temporarily by adding this to `.htaccess`:
```
PassengerFriendlyErrorPages on
```

Check the Passenger log file you set during app creation for detailed error output.

### Notes

- The `uploads/` and `extracted/` folders will be created automatically on first run inside your app root
- 50 MB upload limit is enforced by Flask — to raise it edit `MAX_CONTENT_LENGTH` in `packetprobe_server.py`
- The AI assistant requires users to paste their own Anthropic API key — no server-side key needed

---

## License

MIT — free to use, modify, and distribute.

---

*Built with Python · Flask · dpkt · Pillow · Claude AI*
