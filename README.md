# Mac Sentinel Synthesis Scanner

A single-file, dependency-free daily security report for macOS **standard (non-admin)**
accounts. It reads what's already visible to a normal user — no `sudo`, no third-party
Python packages, no network calls — and renders everything into one offline HTML
dashboard.

Built for people who don't have admin rights on their own Mac (managed/work machines,
shared family computers, etc.) but still want a daily sanity check on what's talking to
the network, whether Gatekeeper/FileVault/SIP are intact, and whether anything new has
wired itself into login items, shell profiles, cron, or browser extensions.

## What it checks

- **Network** — snapshots active connections and listening sockets via `lsof` and
  `nettop`. Flags connections to ports commonly associated with remote shells, Tor, or
  miners; binaries running from `/tmp`, `Downloads`, or other throwaway locations;
  processes going online for the first time; and large daily uploads. Routine
  all-interfaces listeners (Apple Continuity's `rapportd`, cloud-sync LAN discovery like
  `DropboxFileProvider`, etc.) are called out as `info`, not `medium` — visible, not
  alarming.
- **Host firewalls** — Little Snitch and Objective-See's LuLu: installed, running, and
  recent block events.
- **Gatekeeper / SIP / FileVault / firewall / XProtect** — reads posture via `spctl`,
  `csrutil`, `fdesetup`, and the Application Firewall, checks XProtect definition age,
  and audits `~/Downloads` and `~/Applications` for unsigned binaries or files whose
  quarantine flag was suspiciously stripped.
- **Endpoint scanners** — Malwarebytes, plus Objective-See's BlockBlock, OverSight,
  KnockKnock, and RansomWhere?, and ClamAV, if present: installed/running state and any
  readable threat/quarantine log lines.
- **Persistence watchdog** — fingerprints LaunchAgents/LaunchDaemons, shell profiles
  (`.zshrc` and friends), crontab, and Chrome/Brave/Edge/Arc/Firefox extensions against a
  saved baseline, and flags anything new, changed, or removed. Shell profiles are also
  scanned against a small set of known dropper/reverse-shell patterns.

Everything renders into one static HTML file with an embedded CSP (`default-src 'none'`)
and all dynamic content HTML-escaped — the report itself makes zero network requests.

## Requirements

- macOS with the Python 3 that ships with Apple's Command Line Tools (3.9+). No `pip`
  installs, no virtualenv.
- A standard (non-admin) account works fine; some checks (e.g. the unified log, raw
  packet capture) degrade gracefully without root instead of failing.

## Quick start

```bash
# One-off report
python3 mac_sentinel_synthesis_scanner.py report --open

# Preview the dashboard with sample data (no scanning, works on any OS)
python3 mac_sentinel_synthesis_scanner.py demo --open
```

## Running it on your Mac (standard account)

1. **Run the permission check first.** macOS gates access to folders like Downloads
   behind a privacy permission (TCC), separately from file permissions — this script
   just tells you up front which checks are already covered and which module would
   come back `partial` until you grant one:

   ```bash
   bash mac_sec_diagnostic.sh
   ```

   It's read-only: no `sudo`, no writes, no network calls. It only reports what it
   finds and, for anything missing, the exact Setting to open to fix it.

2. **Generate and open your live HTML report:**

   ```bash
   python3 mac_sentinel_synthesis_scanner.py report --open
   ```

   This writes a zero-dependency, offline HTML file to
   `~/MacSentinelSynthesisScanner/latest.html` (and archives daily copies in
   `~/MacSentinelSynthesisScanner/reports/`).

3. **Automate daily background collection (optional, no `sudo` required):**

   ```bash
   python3 mac_sentinel_synthesis_scanner.py install
   python3 mac_sentinel_synthesis_scanner.py rebaseline
   ```

   This installs two **user-level** LaunchAgents in `~/Library/LaunchAgents`: one that
   snapshots `lsof`/`nettop` every 15 minutes, and one that rebuilds `latest.html` every
   morning at 7:00 AM. `rebaseline` right after installing so the scanner's own new
   LaunchAgents don't show up as a "new persistence item" on the next report.

## Commands

| Command                       | What it does                                                         |
|--------------------------------|-----------------------------------------------------------------------|
| `sample`                       | Take one network snapshot (intended to run every 15 min)             |
| `report [--open] [--out PATH]` | Collect everything and write the HTML dashboard                     |
| `install [--hour H] [--interval M]` | Install two **user-level** LaunchAgents (sampler + daily report) |
| `uninstall`                    | Remove those LaunchAgents                                            |
| `rebaseline`                   | Accept the current persistence items as the new "known good"         |
| `demo [--out PATH] [--open]`   | Write a dashboard filled with sample data, for previewing the UI     |

`install` only writes to `~/Library/LaunchAgents` (no `/Library`, no `sudo`) and can be
fully undone with `uninstall`.

## Where data lives

Everything is stored under `~/MacSentinelSynthesisScanner/` (`reports/` and `state/`).
Nothing is ever uploaded anywhere — there are no network calls in the collector or the
report template.

## Known limitations

- Some checks (unified log queries, raw packet capture) need admin rights and silently
  fall back to a lower-fidelity source when run as a standard user; the dashboard's
  module status always says which mode it ran in.
- LuLu's plain-text log format/location is a best-effort guess (Little Snitch is read
  through its own documented CLI/JSON interface instead, which is more reliable).
- Keyword-based log matching (for Malwarebytes/Objective-See threat lines) is a
  heuristic, not a parser — it's tuned to avoid obvious false positives (e.g. matching
  "malware" inside the string "malwarebytes"), but new log formats from
  not-yet-tested tools may need similar tuning over time.

## License

MIT — see [LICENSE](LICENSE).

## Author

[Brian Nibley](https://github.com/Brian-Nibley)
