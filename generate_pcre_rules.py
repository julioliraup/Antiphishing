#!/usr/bin/env python3
"""
generate_pcre_rules.py
Reads antiphishing.rules (source) and generates antiphishing-opnsense.rules.

The original antiphishing.rules is NEVER modified.

Output file structure (OPNsense variant)
─────────────────────────────────────────
  1. Header  (same as source, with updated timestamp)
  2. SID 6000002 — alert ipv4  (inline IP group from phishing_ips.lst; no PCRE)
  3. All alert http rules preserved verbatim from source

Why no DNS/TLS PCRE rules here?
  Suricata 8 JIT-compiles every PCRE pattern at engine start.  With 241 k
  domains split into ~934 chunks of 7 500 chars each (per protocol), that means
  ~1 868 PCRE compilations before the first packet is processed.  On OPNsense
  hardware (APU / mini-PC / embedded) this causes an OOM kill during startup.

  The HTTP rules already provide precise URL-level blocking for every known
  phishing URL.  The inline IP rule covers direct-IP access without any PCRE
  overhead.  This combination is effective and fits within OPNsense memory
  constraints.

Suricata 8 compatibility notes
  • ip rule → inline destination group [ip1,ip2,...] in the rule header;
              no external dataset file required (avoids the OPNsense
              .lst-path resolution bug documented in past conversations)
"""

import re
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOURCE_RULES     = "antiphishing.rules"      # read-only source
OUTPUT_RULES     = "antiphishing-opnsense.rules"  # generated output
PHISHING_LST     = "phishing.lst"
PHISHING_IPS_LST = "phishing_ips.lst"

# SID assignments
# 6000000 and 6000001 are reserved in antiphishing.rules (dataset DNS/TLS).
# The OPNsense variant does NOT emit DNS/TLS PCRE rules — see module docstring.
SID_IP = 6000002   # ipv4 rule (single, inline group; no PCRE)

# Shared rule metadata
REF_GITHUB  = "github.com/julioliraup/Antiphishing"
REF_SIG     = "julioliraup.github.io/AT/signature.html?sid={sid}"
CLASSTYPE   = "social-engineering"
META_DOMAIN = "signature_severity Major, created_et 2025_02_19"
META_IP     = "signature_severity Major, created_et 2026_08_14"

# ---------------------------------------------------------------------------
# Rule builder
# ---------------------------------------------------------------------------

def ip_rule(ip_list: list[str]) -> str:
    """
    Build a Suricata 8 alert ip rule with an inline destination IP group.
    The [ip1,ip2,...] syntax is native to Suricata's rule parser — no external
    dataset file is needed, which sidesteps the OPNsense .lst path issue.
    """
    group = "[" + ",".join(ip.strip() for ip in ip_list if ip.strip()) + "]"
    return (
        f'alert ipv4 $HOME_NET any -> {group} any ('
        f'msg:"AT IP to phishing host - Phishing"; '
        f'reference:url,{REF_GITHUB}; '
        f'reference:url,{REF_SIG.format(sid=SID_IP)}; '
        f'classtype:{CLASSTYPE}; '
        f'sid:{SID_IP}; rev:1; '
        f'metadata: {META_IP};)'
    )

# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

def load_ips(path: str) -> list[str]:
    """phishing_ips.lst: one IPv4 address per line, comments with #."""
    ips = []
    with open(path, "r") as fh:
        for line in fh:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                ips.append(ip)
    return ips

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # ── 1. Read source rules file ───────────────────────────────────────────
    print(f"[*] Reading {SOURCE_RULES} ...")
    with open(SOURCE_RULES, "r") as fh:
        lines = fh.readlines()

    # Split into: header block (leading comments/blanks) + body lines
    header_lines: list[str] = []
    body_lines:   list[str] = []
    in_header = True
    for line in lines:
        if in_header and (line.startswith("#") or line.strip() == ""):
            header_lines.append(line)
        else:
            in_header = False
            body_lines.append(line)

    # ── 2. Collect HTTP rules (verbatim) ────────────────────────────────────
    http_rules: list[str] = []
    for line in body_lines:
        s = line.strip()
        if s.startswith("alert http ") or s == "":
            http_rules.append(line)

    # Strip trailing blank lines from http_rules to avoid double spacing
    while http_rules and http_rules[-1].strip() == "":
        http_rules.pop()

    print(f"[*] Preserved {len(http_rules)} HTTP rule lines from source.")

    # ── 3. Load IP intelligence data ────────────────────────────────────────
    print(f"[*] Loading IPs from {PHISHING_IPS_LST} ...")
    ips = load_ips(PHISHING_IPS_LST)
    print(f"[*] Found {len(ips)} IPs.")

    # ── 4. Build output ─────────────────────────────────────────────────────

    # Update timestamp in header
    now_str = datetime.now(timezone(timedelta(hours=-3))).strftime(
        "%Y-%m-%d %H:%M:%S GMT-0300"
    )
    header = "".join(header_lines)
    header = re.sub(r"(# Last updated:).*", rf"\1 {now_str}", header)

    # ── 5. Assemble and write output ────────────────────────────────────────
    out_parts: list[str] = []

    out_parts.append(header.rstrip("\n"))
    out_parts.append("")
    out_parts.append(ip_rule(ips))
    out_parts.append("")

    for line in http_rules:
        out_parts.append(line.rstrip("\n"))

    output = "\n".join(out_parts)
    if not output.endswith("\n"):
        output += "\n"

    with open(OUTPUT_RULES, "w") as fh:
        fh.write(output)

    print(
        f"[+] Written 1 IP rule + {len([l for l in http_rules if l.strip().startswith('alert')])} HTTP rules."
    )
    print(f"[+] DNS/TLS PCRE rules omitted (OPNsense memory constraint — see module docstring).")
    print(f"[+] Output: {OUTPUT_RULES}  (source {SOURCE_RULES} untouched)")


if __name__ == "__main__":
    main()
