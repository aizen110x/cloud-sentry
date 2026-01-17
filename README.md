# Cloud-Sentry: AWS S3 Security Scanner

<div align="center">

🔍 **Cross-platform Python tool for identifying misconfigured AWS S3 buckets**

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-brightgreen.svg)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-red.svg)](https://github.com)

</div>

---

## ⚠️ Legal Disclaimer

**This tool is for AUTHORIZED security testing only.**

- Unauthorized access to computer systems is illegal
- Use only on systems you own or have explicit permission to test
- The authors are not responsible for misuse or damage caused by this tool
- Always comply with applicable laws and regulations

---

## ✨ What's New in v2.0

- ✅ **No Deprecation Warnings** - Python 3.16+ compatible
- 📊 **HTML Report Generation** - Beautiful, professional reports with styling
- 📁 **CSV Export** - Easy data analysis in Excel/spreadsheets  
- ⏱️ **Scan Duration Tracking** - See how long your scans take
- 📈 **Progress Percentages** - Real-time progress with X/Y (%)
- 📊 **Success Rate Statistics** - See your bucket discovery rate

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation

**1. Install Dependencies:**

```bash
# All Platforms
pip install aiohttp colorama
```

**2. Download the Tool:**

```bash
# Option 1: Clone repository
git clone https://github.com/your-repo/cloud-sentry.git
cd cloud-sentry

# Option 2: Direct download
curl -O https://raw.githubusercontent.com/your-repo/cloud-sentry/main/cloud_sentry.py
```

**3. Run a Basic Scan:**

```bash
python cloud_sentry.py -t tesla
```

---

## 📖 Usage

### Basic Syntax

```bash
python cloud_sentry.py -t <target> [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t`, `--target` | Target company/keyword (required) | - |
| `-o`, `--output` | Output JSON file path | `results.json` |
| `--html` | Generate HTML report | - |
| `--csv` | Generate CSV report | - |
| `--concurrent` | Maximum concurrent requests | `50` |
| `--timeout` | HTTP request timeout (seconds) | `10` |
| `-v`, `--verbose` | Enable verbose output | `False` |
| `--no-color` | Disable colored output | `False` |
| `--no-banner` | Skip ASCII banner | `False` |

### Examples

#### Basic Scan
```bash
# Linux/macOS/Kali
python3 cloud_sentry.py -t tesla

# Windows
python cloud_sentry.py -t tesla
```

#### Full Report Generation (NEW in v2.0!)
```bash
# Generate JSON + HTML + CSV reports
python cloud_sentry.py -t uber --html report.html --csv report.csv

# HTML only
python cloud_sentry.py -t company --html company_scan.html

# CSV only  
python cloud_sentry.py -t target --csv scan_export.csv
```

#### Custom Output Locations
```bash
# Linux/macOS - Save to Desktop
python3 cloud_sentry.py -t uber -o ~/Desktop/results.json --html ~/Desktop/report.html

# Windows CMD - Save to Desktop
python cloud_sentry.py -t uber -o %USERPROFILE%\\Desktop\\results.json --html %USERPROFILE%\\Desktop\\report.html

# Windows PowerShell - Save to Desktop
python cloud_sentry.py -t uber -o "$env:USERPROFILE\\Desktop\\results.json" --html "$env:USERPROFILE\\Desktop\\report.html"
```

#### High-Speed Scan
```bash
python cloud_sentry.py -t acme --concurrent 100 --timeout 15 --html fast_scan.html
```

#### Verbose Mode
```bash
python cloud_sentry.py -t company -v --csv details.csv
```

---

## 📊 Output Formats

### 1. JSON (Default)
Standard machine-readable format with complete scan data.

```json
{
  "scan_info": {
    "target": "tesla",
    "timestamp": "2026-01-17T12:40:27+00:00",
    "platform": "Windows",
    "python_version": "3.14.2",
    "total_checked": 85,
    "total_found": 22,
    "total_vulnerable": 0
  },
  "findings": [...]
}
```

### 2. HTML Report (NEW!)
Professional, styled reports perfect for presentations and stakeholders.

**Features:**
- Modern gradient design with responsive layout
- Color-coded risk levels (CRITICAL, HIGH, MEDIUM, LOW)
- Summary statistics dashboard
- Detailed findings with clickable URLs
- Platform and scan date information
- Print-friendly styling

### 3. CSV Export (NEW!)
Lightweight format for data analysis and spreadsheets.

```csv
bucket_name,url,exists,accessible,listable,writable,risk_level,timestamp
tesla-backup,https://tesla-backup.s3.amazonaws.com,True,False,False,False,LOW,2026-01-17T12:40:27+00:00
```

---

## 🔍 How It Works

1. **Bucket Name Generation**: Generates 100-200 potential bucket names based on:
   - Common prefixes (backup-, cdn-, static-, dev-, prod-, etc.)
   - Common suffixes (-backup, -logs, -assets, -prod, etc.)
   - AWS regions (-us-east-1, -eu-west-1, etc.)
   - Environment variations (-dev, -test, -staging, -production)

2. **Asynchronous Scanning**: Uses aiohttp for concurrent HTTP requests
   - Checks bucket existence (HEAD request)
   - Tests public listability (GET request)
   - Detects permissions and access levels

3. **Risk Assessment**:
   - **CRITICAL**: Publicly listable buckets (anyone can view contents)
   - **LOW**: Bucket exists but is not publicly accessible
   - **SAFE**: Bucket doesn't exist or is properly secured

4. **Results Export**: Saves findings to JSON, HTML, and/or CSV formats

---

## 📈 New Features in v2.0

### Scan Duration Tracking
See exactly how long your scans take:
```
Scan Duration: 8.45s
```

### Progress with Percentages
Real-time progress updates:
```
Progress: 45/85 (52.9%) | 12 found | 2 vulnerable
```

### Success Rate Statistics
Understand your discovery rate:
```
Buckets Found: 22 (25.9% success rate)
```

---

## 🛠️ Troubleshooting

### "python: command not found"

**Linux/macOS:**
```bash
# Use python3 instead
python3 cloud_sentry.py -t tesla
```

**Windows:**
```cmd
# Use py launcher
py cloud_sentry.py -t tesla

# OR add Python to PATH
# Add C:\\Python3x\\ to system PATH environment variable
```

### "Module not found: aiohttp" or "Module not found: colorama"

```bash
# All Platforms
pip install aiohttp colorama

# If pip not found (Linux/macOS)
python3 -m pip install aiohttp colorama

# If pip not found (Windows)
python -m pip install aiohttp colorama

# If permission denied (Linux/macOS)
pip3 install --user aiohttp colorama
```

### Colors Not Showing (Windows CMD)

- Make sure colorama is installed: `pip install colorama`
- Use Windows Terminal instead of legacy CMD
- Or use `--no-color` flag to disable colors

---

## 🎯 Advanced Usage

### Batch Scanning
```bash
# Scan multiple targets
for target in company1 company2 company3; do
  python3 cloud_sentry.py -t $target --html "${target}_report.html"
done
```

### Scheduled Scans

**Linux/macOS (cron):**
```bash
# Edit crontab
crontab -e

# Add scheduled scan (daily at 2 AM)
0 2 * * * python3 /path/to/cloud_sentry.py -t company --html /var/log/scan_$(date +\%Y\%m\%d).html
```

**Windows (Task Scheduler):**
```
1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (e.g., Daily at 2:00 AM)
4. Action: Start a program
   - Program: python
   - Arguments: C:\\path\\to\\cloud_sentry.py -t company --html C:\\logs\\scan.html
```

---

## 🔒 Security Considerations

- This tool performs **active reconnaissance** - use responsibly
- High concurrent request rates may trigger AWS rate limiting
- Some organizations may consider scanning as hostile activity
- Always obtain proper authorization before testing
- Review local laws and regulations regarding security testing

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- Built with [aiohttp](https://docs.aiohttp.org/) for async HTTP requests
- Uses [colorama](https://pypi.org/project/colorama/) for cross-platform colored output

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check the troubleshooting section above
- Review platform-specific installation guides

---

<div align="center">

**Made with ❤️ for security researchers**

*Remember: With great power comes great responsibility*

**Version 2.0** - Now with HTML reports, CSV export, and enhanced statistics!

</div>
