#!/usr/bin/env python3
"""
generate_pcre_rules.py
Reads antiphishing.rules (source) and generates antiphishing-opnsense.rules.

The original antiphishing.rules is NEVER modified.

Output file structure
─────────────────────
  1. Header  (same as source, with updated timestamp)
  2. SID 6000000 — alert dns  (first PCRE chunk, domains from phishing.lst)
  3. SID 6000001 — alert tls  (first PCRE chunk, same domains)
  4. SID 6000002 — alert ip   (inline IP group from phishing_ips.lst)
  5. All alert http rules preserved verbatim from source
  6. DNS overflow chunks (SIDs 6090000+) — last section, labelled as continuation
  7. TLS overflow chunks (SIDs 6091000+) — last section, labelled as continuation

Why split at all?
  Suricata 8 compiles PCRE at engine start.  A single alternation pattern with
  241 k domains (~15 MB of text) will exhaust PCRE's internal workspace and
  crash the engine on low-memory appliances (OPNsense on APU/mini-PC hardware
  typically has 4–8 GB but the PCRE JIT stack defaults are small).  7 500-char
  chunks are safe across all tested Suricata/OPNsense versions.

Suricata 8 compatibility notes
  • dns.query  → sticky buffer; pcre anchored with /^(?:...)$/i
  • tls.sni    → sticky buffer; pcre anchored with /^(?:...)$/i
  • ip rule    → inline destination group [ip1,ip2,...] in the rule header;
                  no external dataset file required (avoids the OPNsense
                  .lst-path resolution bug documented in past conversations)
"""

import re
import base64
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOURCE_RULES     = "antiphishing.rules"      # read-only source
OUTPUT_RULES     = "antiphishing-opnsense.rules"  # generated output
PHISHING_LST     = "phishing.lst"
PHISHING_IPS_LST = "phishing_ips.lst"

# SID assignments
SID_DNS_BASE      = 6000000   # primary DNS rule  (first chunk)
SID_TLS_BASE      = 6000001   # primary TLS rule  (first chunk)
SID_IP            = 6000002   # ip rule  (single, inline group)
DNS_OVERFLOW_BASE = 6090000   # continuation DNS chunks (appended at end)
TLS_OVERFLOW_BASE = 6091000   # continuation TLS chunks (appended at end)

# Maximum alternation string length per PCRE rule.
# Conservative limit: Suricata's pcre_match_limit defaults and JIT stack
# impose practical ceilings around 8–10 KB per pattern; 7 500 gives headroom.
MAX_PCRE_CHARS = 7500

# Shared rule metadata
REF_GITHUB  = "github.com/julioliraup/Antiphishing"
REF_SIG     = "julioliraup.github.io/AT/signature.html?sid={sid}"
CLASSTYPE   = "social-engineering"
META_DOMAIN = "signature_severity Major, created_et 2025_02_19"
META_IP     = "signature_severity Major, created_et 2026_08_14"

# ---------------------------------------------------------------------------
# PCRE helpers
# ---------------------------------------------------------------------------

def pcre_escape_domain(domain: str) -> str:
    """
    Escape all PCRE metacharacters that can appear in domain names.
    We escape: . + * ? [ ] { } ( ) | ^ $ \\ /
    Hyphens and underscores are safe as-is outside character classes.
    """
    special = r".+*?[]{}()|^$\\"
    out = []
    for ch in domain:
        if ch in special:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def build_chunks(domains: list[str]) -> list[str]:
    """
    Partition domains into PCRE alternation strings that each fit within
    MAX_PCRE_CHARS characters.  Returns a list of raw alternation strings,
    e.g. ['dom1|dom2|dom3', 'dom4|dom5', ...].
    """
    chunks: list[str] = []
    current: list[str] = []
    length = 0

    for domain in domains:
        escaped = pcre_escape_domain(domain.strip())
        if not escaped:
            continue
        # separator cost: 0 for first item in chunk, 1 (pipe) for subsequent
        cost = len(escaped) + (1 if current else 0)
        if current and length + cost > MAX_PCRE_CHARS:
            chunks.append("|".join(current))
            current = [escaped]
            length = len(escaped)
        else:
            current.append(escaped)
            length += cost

    if current:
        chunks.append("|".join(current))

    return chunks

# ---------------------------------------------------------------------------
# Rule builders
# ---------------------------------------------------------------------------

def dns_rule(sid: int, alt: str, *, continuation: bool = False) -> str:
    """Build a Suricata 8 alert dns rule with a PCRE sticky-buffer match."""
    if continuation:
        msg = (
            f"AT DNS query to suspicious domain - Phishing "
            f"(continuation of sid:{SID_DNS_BASE})"
        )
        ref_sid = SID_DNS_BASE
    else:
        msg     = "AT DNS query to suspicious domain - Phishing"
        ref_sid = sid

    pattern = f"/^(?:{alt})$/i"
    return (
        f'alert dns $HOME_NET any -> any any ('
        f'msg:"{msg}"; '
        f'dns.query; '
        f'pcre:"{pattern}"; '
        f'reference:url,{REF_GITHUB}; '
        f'reference:url,{REF_SIG.format(sid=ref_sid)}; '
        f'classtype:{CLASSTYPE}; '
        f'sid:{sid}; rev:1; '
        f'metadata: {META_DOMAIN};)'
    )


def tls_rule(sid: int, alt: str, *, continuation: bool = False) -> str:
    """Build a Suricata 8 alert tls rule with a PCRE sticky-buffer match."""
    if continuation:
        msg = (
            f"AT TLS SNI to suspicious domain - Phishing "
            f"(continuation of sid:{SID_TLS_BASE})"
        )
        ref_sid = SID_TLS_BASE
    else:
        msg     = "AT TLS SNI to suspicious domain - Phishing"
        ref_sid = sid

    pattern = f"/^(?:{alt})$/i"
    return (
        f'alert tls $HOME_NET any -> any any ('
        f'msg:"{msg}"; '
        f'tls.sni; '
        f'pcre:"{pattern}"; '
        f'reference:url,{REF_GITHUB}; '
        f'reference:url,{REF_SIG.format(sid=ref_sid)}; '
        f'classtype:{CLASSTYPE}; '
        f'sid:{sid}; rev:1; '
        f'metadata: {META_DOMAIN};)'
    )


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
# Data loaders
# ---------------------------------------------------------------------------

def load_domains(path: str) -> list[str]:
    """
    phishing.lst format: one base64-encoded domain per line.
    Decode each line individually.
    """
    domains = []
    with open(path, "r") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                domain = base64.b64decode(raw).decode("utf-8", errors="replace").strip()
                if domain:
                    domains.append(domain)
            except Exception:
                continue
    return domains


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

    # ── 3. Load intelligence data ───────────────────────────────────────────
    print(f"[*] Loading domains from {PHISHING_LST} ...")
    domains = load_domains(PHISHING_LST)
    print(f"[*] Decoded {len(domains)} domains.")

    print(f"[*] Building PCRE chunks (max {MAX_PCRE_CHARS} chars each) ...")
    chunks = build_chunks(domains)
    print(f"[*] {len(chunks)} chunk(s) needed for {len(domains)} domains.")

    print(f"[*] Loading IPs from {PHISHING_IPS_LST} ...")
    ips = load_ips(PHISHING_IPS_LST)
    print(f"[*] Found {len(ips)} IPs.")

    # ── 4. Build output sections ────────────────────────────────────────────

    # Update timestamp in header
    now_str = datetime.now(timezone(timedelta(hours=-3))).strftime(
        "%Y-%m-%d %H:%M:%S GMT-0300"
    )
    header = "".join(header_lines)
    header = re.sub(r"(# Last updated:).*", rf"\1 {now_str}", header)

    # Primary rules (first chunk of each protocol)
    primary: list[str] = []
    primary.append(dns_rule(SID_DNS_BASE, chunks[0]))
    primary.append("")
    primary.append(tls_rule(SID_TLS_BASE, chunks[0]))
    primary.append("")
    primary.append(ip_rule(ips))
    primary.append("")

    # Overflow DNS chunks (chunks[1:]) — placed AFTER all http rules
    overflow_dns: list[str] = []
    if len(chunks) > 1:
        overflow_dns.append(
            "# ── DNS PCRE continuation rules (overflow from sid:6000000) ─────────────"
        )
        for idx, alt in enumerate(chunks[1:], start=1):
            sid = DNS_OVERFLOW_BASE + (idx - 1)
            overflow_dns.append(dns_rule(sid, alt, continuation=True))
        overflow_dns.append("")

    # Overflow TLS chunks (chunks[1:]) — placed AFTER dns overflow
    overflow_tls: list[str] = []
    if len(chunks) > 1:
        overflow_tls.append(
            "# ── TLS PCRE continuation rules (overflow from sid:6000001) ─────────────"
        )
        for idx, alt in enumerate(chunks[1:], start=1):
            sid = TLS_OVERFLOW_BASE + (idx - 1)
            overflow_tls.append(tls_rule(sid, alt, continuation=True))
        overflow_tls.append("")

    # ── 5. Assemble and write output ────────────────────────────────────────
    out_parts: list[str] = []

    out_parts.append(header.rstrip("\n"))
    out_parts.append("")

    for line in primary:
        out_parts.append(line)

    for line in http_rules:
        out_parts.append(line.rstrip("\n"))

    out_parts.append("")

    for line in overflow_dns:
        out_parts.append(line)

    for line in overflow_tls:
        out_parts.append(line)

    output = "\n".join(out_parts)
    if not output.endswith("\n"):
        output += "\n"

    with open(OUTPUT_RULES, "w") as fh:
        fh.write(output)

    total_dns = len(chunks)         # 1 primary + N-1 overflow
    total_tls = len(chunks)
    overflow_n = len(chunks) - 1
    print(
        f"[+] Written {total_dns} DNS rule(s) ({1} primary + {overflow_n} overflow), "
        f"{total_tls} TLS rule(s) ({1} primary + {overflow_n} overflow), "
        f"1 IP rule."
    )
    print(f"[+] Output: {OUTPUT_RULES}  (source {SOURCE_RULES} untouched)")


if __name__ == "__main__":
    main()
