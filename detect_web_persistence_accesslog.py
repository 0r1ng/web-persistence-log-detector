#!/usr/bin/env python3
import argparse
import gzip
import html
import json
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote_plus, urlsplit, parse_qsl

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

REQ_RE = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[0-9.]+$',
    re.IGNORECASE
)

SCRIPT_EXT_RE = re.compile(
    r'\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|asmx|cgi|pl|py|rb|sh)(?:$|[/?#;])',
    re.IGNORECASE
)

KNOWN_SHELL_RE = re.compile(
    r'(?i)(^|/)'
    r'(shell|cmd|command|webshell|wso|c99|r57|b374k|p0wny|weevely|alfa|indoxploit|'
    r'backdoor|rootshell|priv8|mini|mini_shell|mailer|bypass|filemanager|up|upload_shell|'
    r'kacak|marijuana|sadrazam|anon|adminer|ak47|lol|xleet)'
    r'\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|py|rb|sh)(?:$|[/?#;])'
)

WRITABLE_SCRIPT_RE = re.compile(
    r'(?i)/(uploads?|files?|images?|img|media|assets?|static|cache|tmp|temp|backup|backups|'
    r'wp-content/uploads|sites/default/files|storage|public|download|downloads)/[^?#"]*'
    r'\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|py|rb|sh)(?:$|[/?#;])'
)

UPLOAD_ENDPOINT_RE = re.compile(
    r'(?i)(upload|filemanager|elfinder|connector|ckeditor|fckeditor|tinymce|async-upload|'
    r'plugin-editor|theme-editor|media-new|uploadify)'
)

HIDDEN_SCRIPT_RE = re.compile(
    r'(?i)/\.[a-z0-9_.-]+\.(php|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|py|rb|sh)(?:$|[/?#;])'
)

CMD_PARAM_NAMES = {
    "cmd", "command", "exec", "execute", "shell", "sh", "bash", "powershell",
    "ps", "code", "payload", "run", "c", "x", "do", "action"
}

CMD_VALUE_RE = re.compile(
    r'(?i)\b(whoami|id|uname|hostname|pwd|ls|cat|head|tail|ifconfig|ipconfig|net\s+user|'
    r'cmd\.exe|powershell|bash\s+-c|sh\s+-c|python\s+-c|python3\s+-c|perl\s+-e|php\s+-r|'
    r'wget|curl|chmod|chown|nc\s|ncat|socat|telnet|/bin/sh|/bin/bash|/dev/tcp|'
    r'base64\s+-d|certutil|bitsadmin|mshta|rundll32)\b'
)

AUTOMATION_UA_RE = re.compile(
    r'(?i)(curl|wget|python-requests|go-http-client|libwww-perl|nikto|sqlmap|nuclei|nessus|acunetix)'
)

SUCCESS_STATUSES = {"200", "201", "202", "204", "206", "301", "302", "303"}


def open_log(path):
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="ignore")
    return open(path, "r", errors="ignore")


def decode_many(value, rounds=6):
    value = html.unescape(value)
    for _ in range(rounds):
        new_value = unquote_plus(value)
        new_value = html.unescape(new_value)
        if new_value == value:
            break
        value = new_value
    return value


def parse_time(value):
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        return None


def parse_line(line):
    m = LOG_RE.match(line)
    if not m:
        return None

    request = m.group("request")
    rm = REQ_RE.match(request)
    if not rm:
        return None

    target_raw = rm.group("target")
    target = decode_many(target_raw)

    try:
        split = urlsplit(target)
        path = split.path
        query = split.query
    except Exception:
        path = target
        query = ""

    return {
        "ip": m.group("ip"),
        "time_raw": m.group("time"),
        "time": parse_time(m.group("time")),
        "method": rm.group("method").upper(),
        "target_raw": target_raw,
        "target": target,
        "path": path,
        "query": query,
        "status": m.group("status"),
        "size": m.group("size"),
        "referer": m.group("referer"),
        "agent": m.group("agent"),
        "raw": line.rstrip("\n")
    }


def extract_params(query):
    try:
        return parse_qsl(query, keep_blank_values=True)
    except Exception:
        return []


def has_command_evidence(event):
    evidence = []

    for name, value in extract_params(event["query"]):
        name_lower = name.lower()
        decoded_value = decode_many(value)

        if name_lower in CMD_PARAM_NAMES:
            evidence.append("command-like parameter: " + name)

        if CMD_VALUE_RE.search(decoded_value):
            evidence.append("command-like value in parameter " + name + ": " + decoded_value[:120])

    if CMD_VALUE_RE.search(event["target"]):
        evidence.append("command-like payload in URL")

    return evidence


def classify_event(event):
    reasons = []
    score = 0

    success = event["status"] in SUCCESS_STATUSES
    known_shell = bool(KNOWN_SHELL_RE.search(event["target"]))
    writable_script = bool(WRITABLE_SCRIPT_RE.search(event["target"]))
    hidden_script = bool(HIDDEN_SCRIPT_RE.search(event["target"]))
    script_ext = bool(SCRIPT_EXT_RE.search(event["path"]))
    upload_endpoint = bool(UPLOAD_ENDPOINT_RE.search(event["target"]))
    command_evidence = has_command_evidence(event)
    automation_ua = bool(AUTOMATION_UA_RE.search(event["agent"]))

    if not success:
        return None

    if known_shell:
        score += 12
        reasons.append("known web shell or backdoor filename")

    if writable_script:
        score += 10
        reasons.append("executable script inside upload or writable-like directory")

    if hidden_script:
        score += 9
        reasons.append("hidden executable script path")

    if event["method"] == "POST" and script_ext:
        score += 5
        reasons.append("POST request to executable script")

    if event["method"] in {"PUT", "PATCH"} and script_ext:
        score += 10
        reasons.append("file-write method against executable script")

    if upload_endpoint and event["method"] in {"POST", "PUT"}:
        score += 4
        reasons.append("upload or file-manager endpoint used")

    if command_evidence:
        score += 12
        reasons.extend(command_evidence)

    if automation_ua and (known_shell or writable_script or command_evidence):
        score += 3
        reasons.append("automation or scanner user-agent")

    if score >= 18:
        confidence = "VERY_HIGH"
    elif score >= 12:
        confidence = "HIGH"
    elif score >= 8:
        confidence = "MEDIUM"
    else:
        return None

    return {
        "confidence": confidence,
        "score": score,
        "reasons": sorted(set(reasons))
    }


def print_result(filename, line_no, event, finding, json_output):
    record = {
        "file": filename,
        "line": line_no,
        "confidence": finding["confidence"],
        "score": finding["score"],
        "ip": event["ip"],
        "time": event["time_raw"],
        "method": event["method"],
        "status": event["status"],
        "path": event["path"],
        "target": event["target"],
        "user_agent": event["agent"],
        "reasons": finding["reasons"],
        "raw": event["raw"]
    }

    if json_output:
        print(json.dumps(record, ensure_ascii=False))
        return

    print("=" * 120)
    print("CONFIDENCE: " + record["confidence"])
    print("SCORE:      " + str(record["score"]))
    print("FILE:       " + record["file"])
    print("LINE:       " + str(record["line"]))
    print("IP:         " + record["ip"])
    print("TIME:       " + record["time"])
    print("METHOD:     " + record["method"])
    print("STATUS:     " + record["status"])
    print("PATH:       " + record["path"])
    print("TARGET:     " + record["target"])
    print("REASON:     " + ", ".join(record["reasons"]))
    print("RAW:        " + record["raw"])


def print_repeated_alert(filename, events, threshold, json_output):
    grouped = defaultdict(list)

    for event in events:
        if not event["status"] in SUCCESS_STATUSES:
            continue

        if not WRITABLE_SCRIPT_RE.search(event["target"]) and not KNOWN_SHELL_RE.search(event["target"]):
            continue

        grouped[(event["ip"], event["path"])].append(event)

    for (ip, path), group in grouped.items():
        if len(group) < threshold:
            continue

        first = group[0]
        last = group[-1]

        record = {
            "file": filename,
            "confidence": "HIGH",
            "type": "repeated suspicious web persistence access",
            "ip": ip,
            "path": path,
            "count": len(group),
            "first_seen": first["time_raw"],
            "last_seen": last["time_raw"],
            "reason": "same IP repeatedly accessed the same suspicious script path"
        }

        if json_output:
            print(json.dumps(record, ensure_ascii=False))
            continue

        print("=" * 120)
        print("CONFIDENCE: HIGH")
        print("TYPE:       " + record["type"])
        print("FILE:       " + record["file"])
        print("IP:         " + record["ip"])
        print("PATH:       " + record["path"])
        print("COUNT:      " + str(record["count"]))
        print("FIRST:      " + record["first_seen"])
        print("LAST:       " + record["last_seen"])
        print("REASON:     " + record["reason"])


def print_upload_then_shell_alert(filename, events, window_minutes, json_output):
    uploads_by_ip = defaultdict(deque)
    window = timedelta(minutes=window_minutes)

    for event in events:
        if not event["time"]:
            continue

        ip = event["ip"]
        now = event["time"]

        q = uploads_by_ip[ip]
        while q and now - q[0]["time"] > window:
            q.popleft()

        if event["method"] in {"POST", "PUT"} and UPLOAD_ENDPOINT_RE.search(event["target"]):
            q.append(event)

        if WRITABLE_SCRIPT_RE.search(event["target"]) or KNOWN_SHELL_RE.search(event["target"]):
            if q:
                first = q[0]
                record = {
                    "file": filename,
                    "confidence": "VERY_HIGH",
                    "type": "upload endpoint followed by suspicious script access",
                    "ip": ip,
                    "upload_time": first["time_raw"],
                    "script_time": event["time_raw"],
                    "upload_target": first["target"],
                    "script_target": event["target"],
                    "reason": "same IP used upload or file-manager endpoint then accessed executable script in suspicious location"
                }

                if json_output:
                    print(json.dumps(record, ensure_ascii=False))
                    continue

                print("=" * 120)
                print("CONFIDENCE: VERY_HIGH")
                print("TYPE:       " + record["type"])
                print("FILE:       " + record["file"])
                print("IP:         " + record["ip"])
                print("UPLOAD:     " + record["upload_time"] + " " + record["upload_target"])
                print("SCRIPT:     " + record["script_time"] + " " + record["script_target"])
                print("REASON:     " + record["reason"])


def main():
    parser = argparse.ArgumentParser(description="Detect web persistence clues from access.log.")
    parser.add_argument("logs", nargs="+", help="access.log files. Supports .gz. Use - for stdin.")
    parser.add_argument("--json", action="store_true", help="Output JSON lines.")
    parser.add_argument("--include-medium", action="store_true", help="Show MEDIUM confidence findings.")
    parser.add_argument("--repeat-threshold", type=int, default=3, help="Repeated access threshold. Default: 3")
    parser.add_argument("--upload-window-minutes", type=int, default=60, help="Upload-to-shell correlation window. Default: 60")
    parser.add_argument("--debug", action="store_true", help="Show parsed summary.")
    args = parser.parse_args()

    for filename in args.logs:
        parsed = 0
        candidates = 0
        alerts = 0
        all_events = []

        try:
            with open_log(filename) as handle:
                for line_no, line in enumerate(handle, 1):
                    event = parse_line(line)
                    if not event:
                        continue

                    parsed += 1
                    all_events.append(event)

                    finding = classify_event(event)
                    if not finding:
                        continue

                    candidates += 1

                    if finding["confidence"] == "MEDIUM" and not args.include_medium:
                        continue

                    alerts += 1
                    print_result(filename, line_no, event, finding, args.json)

            print_repeated_alert(filename, all_events, args.repeat_threshold, args.json)
            print_upload_then_shell_alert(filename, all_events, args.upload_window_minutes, args.json)

            if args.debug:
                script_paths = [e for e in all_events if SCRIPT_EXT_RE.search(e["path"])]
                writable_scripts = [e for e in all_events if WRITABLE_SCRIPT_RE.search(e["target"])]
                known_shells = [e for e in all_events if KNOWN_SHELL_RE.search(e["target"])]
                upload_events = [e for e in all_events if UPLOAD_ENDPOINT_RE.search(e["target"])]

                print("=" * 120)
                print("DEBUG SUMMARY")
                print("File:                    " + filename)
                print("Parsed lines:            " + str(parsed))
                print("Executable script paths: " + str(len(script_paths)))
                print("Writable script paths:   " + str(len(writable_scripts)))
                print("Known shell names:       " + str(len(known_shells)))
                print("Upload endpoints:        " + str(len(upload_events)))
                print("Direct alert candidates: " + str(candidates))
                print("Printed alerts:          " + str(alerts))

                if alerts == 0:
                    print("No high-confidence web persistence clue was found in this access.log.")
                    print("If the attacker used POST body commands, normal access.log may not contain the payload.")

        except FileNotFoundError:
            print("[ERROR] File not found: " + filename, file=sys.stderr)

        except PermissionError:
            print("[ERROR] Permission denied: " + filename, file=sys.stderr)


if __name__ == "__main__":
    main()
