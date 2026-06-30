# Web Persistence Log Detector

A Python tool for detecting web persistence clues from Apache/Nginx-style access logs.

This tool helps SOC analysts, incident responders, and detection engineers identify possible web shell access, suspicious backdoor usage, command-execution parameters, and upload-to-shell behavior from `access.log` files.

## Description

Attackers often maintain persistence on web servers by uploading or accessing web shells, backdoors, or executable scripts in writable directories such as upload folders.

This script analyzes web access logs and looks for high-confidence persistence clues, including:

* Web shell filenames
* Backdoor-like script names
* Executable files inside upload directories
* Command-like parameters
* Repeated access to suspicious scripts
* Upload endpoint followed by suspicious script access
* Automation or scanner user agents

## Features

* Detects known web shell names such as `shell.php`, `cmd.php`, `wso.php`, `c99.php`, and `r57.php`
* Detects executable scripts inside upload-like directories
* Detects command parameters such as `cmd=`, `exec=`, `shell=`, and `command=`
* Detects command-like values such as `whoami`, `id`, `uname`, `curl`, `wget`, and `/bin/bash`
* Detects repeated suspicious access from the same IP
* Detects upload endpoint followed by suspicious script access
* Supports Apache/Nginx combined access logs
* Supports `.gz` compressed logs
* Supports JSON output
* Includes debug mode for investigation

## Detection Examples

The script can detect suspicious requests such as:

```text
GET /uploads/shell.php?cmd=whoami HTTP/1.1
POST /wp-content/uploads/wso.php HTTP/1.1
GET /uploads/backdoor.php?exec=id HTTP/1.1
GET /images/c99.php?cmd=uname+-a HTTP/1.1
POST /filemanager/upload.php HTTP/1.1
GET /uploads/priv8.php HTTP/1.1
```

## Installation

No external Python packages are required.

Clone the repository:

```bash
git clone https://github.com/yourname/web-persistence-log-detector.git
cd web-persistence-log-detector
```

Make the script executable:

```bash
chmod +x detect_web_persistence_accesslog.py
```

## Usage

Scan one access log:

```bash
python3 detect_web_persistence_accesslog.py access.log
```

Run with debug summary:

```bash
python3 detect_web_persistence_accesslog.py access.log --debug
```

Show medium-confidence findings:

```bash
python3 detect_web_persistence_accesslog.py access.log --include-medium
```

Save results to a text file:

```bash
python3 detect_web_persistence_accesslog.py access.log --include-medium --debug > persistence_hits.txt
```

Output JSON lines:

```bash
python3 detect_web_persistence_accesslog.py access.log --json > persistence_hits.jsonl
```

Scan compressed logs:

```bash
python3 detect_web_persistence_accesslog.py access.log.gz
```

Scan multiple logs:

```bash
python3 detect_web_persistence_accesslog.py *.log
```

## Options

```text
--include-medium
    Show medium-confidence findings.

--json
    Output results as JSON lines.

--repeat-threshold
    Number of repeated suspicious accesses needed to trigger a repeated-access alert.
    Default: 3

--upload-window-minutes
    Time window used to correlate upload endpoints with later suspicious script access.
    Default: 60

--debug
    Show parsing and detection summary.
```

## Example Test

Create a test log:

```bash
cat > test.log << 'EOF'
192.168.1.10 - - [20/Jun/2021:12:36:31 +0300] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 123 "-" "curl/7.68.0"
192.168.1.11 - - [20/Jun/2021:12:37:31 +0300] "POST /filemanager/upload.php HTTP/1.1" 200 321 "-" "Mozilla/5.0"
192.168.1.11 - - [20/Jun/2021:12:38:31 +0300] "GET /uploads/backdoor.php HTTP/1.1" 200 500 "-" "Mozilla/5.0"
192.168.1.20 - - [20/Jun/2021:12:39:31 +0300] "GET /index.php HTTP/1.1" 200 5000 "-" "Mozilla/5.0"
EOF
```

Run the detector:

```bash
python3 detect_web_persistence_accesslog.py test.log --debug
```

## Example Output

```text
========================================================================================================================
CONFIDENCE: VERY_HIGH
SCORE:      37
FILE:       access.log
LINE:       1
IP:         192.168.1.10
TIME:       20/Jun/2021:12:36:31 +0300
METHOD:     GET
STATUS:     200
PATH:       /uploads/shell.php
TARGET:     /uploads/shell.php?cmd=whoami
REASON:     known web shell or backdoor filename, executable script inside upload or writable-like directory, command-like parameter: cmd, command-like value in parameter cmd: whoami
RAW:        192.168.1.10 - - [20/Jun/2021:12:36:31 +0300] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 123 "-" "curl/7.68.0"
```

## Scoring

The script uses a simple scoring system to rank suspicious events.

```text
Score >= 18  VERY_HIGH
Score >= 12  HIGH
Score >= 8   MEDIUM
Score < 8    Ignored
```

Example scoring indicators:

```text
Known web shell filename              +12
Executable script in upload folder    +10
Hidden executable script path         +9
Command-like parameter                +12
POST request to executable script     +5
PUT/PATCH to executable script        +10
Automation user agent                 +3
```

## Recommended SOC Usage

Use this tool during:

* Web server log review
* SOC alert triage
* Incident response
* Threat hunting
* Web shell investigation
* Post-exploitation analysis
* Detection engineering validation

Strong persistence indicators include:

```text
/upload directory + executable script
known shell filename + successful HTTP response
cmd parameter + command value
upload endpoint followed by script access
same IP repeatedly accessing suspicious script
```

## Important Notes

Access logs usually do not contain POST request bodies.

If an attacker sends commands inside a POST body, normal Apache or Nginx access logs may not show the full payload. In that case, review:

* WAF logs
* Reverse proxy logs
* Application logs
* Web server error logs
* File upload logs
* EDR telemetry
* Full packet capture
* Web root file system artifacts

## Limitations

This tool detects web persistence clues from logs. It does not prove compromise by itself.

To confirm the finding, analysts should review:

* File existence on disk
* File creation/modification time
* File owner and permissions
* Web server error logs
* Application logs
* EDR alerts
* Process execution history
* Network callbacks
* Response size and status code

## Security Notice

Use this tool only on logs and systems you own or are authorized to analyze.

## License

MIT License
