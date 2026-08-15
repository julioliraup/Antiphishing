![Antiphishing logo](img/antiphishing.png)
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/julioliraup/Antiphishing) ![GitHub commit activity](https://img.shields.io/github/commit-activity/t/julioliraup/Antiphishing)

[
[DONATE](https://github.com/sponsors/julioliraup) - [DASHBOARD VECTORS](https://julioliraup.github.io/AT) - [CONTRIBUTING](./CONTRIBUTING.md) - [SUBMIT A VECTOR](/julioliraup/Antiphishing/issues/new?q=state%3Aopen+label%3A%22Phishing+Vector%22) - [REST API CTI](https://github.com/julioliraup/AT/wiki/REST-API-USE) - [WIKI](/julioliraup/Antiphishing/wiki)
]

> Advanced Phishing Protection: Suricata rulesets open and free

# Functionality

This rule is built using malicious URLs and domains involved in phishing attacks. We utilize some community APIs and NRD (Newly Registered Domain) to construct these rules, and with them, we create TLS, DNS, and HTTP rules.

Our sources:
1. [Phishstats](https://phishstats.info)
2. [Openphish](https://openphish.com/)
3. [cbuijs/nrd](https://github.com/cbuijs/nrd) — Newly Registered Domain with DNS traffic 

**Dataset loading:** The DNS and TLS signatures load `phishing.lst` directly through Suricata's dataset keyword. This ensures the phishing domain dataset is self-contained and does not require a separate `suricata.yaml` dataset declaration, which is especially important for packaged deployments such as OPNsense. **After updating `phishing.lst`, the Suricata ruleset must be reloaded for the updated dataset to become active.** See the Suricata documentation for details on dataset loading and rule reload behavior.

Contribution: [CONTRIBUTING.md](https://github.com/julioliraup/Antiphishing/blob/main/CONTRIBUTING.md)

# Installation guide
  <a href="https://github.com/julioliraup/Antiphishing/wiki/Configuration-Ruleset-on-GNU-Linux">
    <img height="100" alt="Configuration-Ruleset-on-GNU-Linux" src="https://github.com/user-attachments/assets/859b9e29-a650-48b2-968c-628e8c345b5b" />
<img height="100" alt="Configuration-Ruleset-on-cearos" src="https://github.com/user-attachments/assets/083098a4-64b9-4c29-994d-75dcd61fa695" />
  </a>

  <a href="https://github.com/julioliraup/Antiphishing/wiki/Configuration-Ruleset-on-pfSense">
    <img height="100" alt="Configuration-Ruleset-on-pfSense" src="https://github.com/user-attachments/assets/55fcc78d-af99-4e7f-9022-75b644f3c497" />
  </a>

  <a href="https://github.com/julioliraup/Antiphishing/wiki/Configuration:-Antiphishing-Ruleset-on-IDSTower">
    <img height="90" alt="Configuration: Antiphishing Ruleset on IDSTower" src="https://github.com/user-attachments/assets/1044e7a6-13fa-48f4-bbfc-1a7662f5afd0" />
  </a>

  [<img height="90" alt="OPNsense  julioliraup/antiphishing ruleset on Suricata" src="https://github.com/user-attachments/assets/551b04de-b34c-4856-85b7-1928639bc6ec" />](https://github.com/julioliraup/Antiphishing/wiki/Quick-Guide:-Installing-Antiphishing-on-OPNsense-(-=-26.7.2))

## Upcoming Guides

<img height="100" alt="IPFire julioliraup/antiphishing ruleset on intrusion prevention" src="https://github.com/user-attachments/assets/a8f0e322-7d18-4219-b5fb-32188e2207a3"/>

# General info
The ruleset is the `antiphishing.rules` file, which contains three dataset rules (DNS, TLS, IP). The DNS and TLS rules depend on a `phishing.lst` list; the IP reputation rule depends on a `phishing_ips.lst` list. Note that `phishing_ips.lst` is a `type ipv4` dataset, so it holds plain-text addresses one per line, unlike `phishing.lst` which is base64-encoded. Finally, there is another file named `antiphishing.rules.md5` for integrity verification. We provide a compressed file containing these mentioned files, which are constantly updated without changing the URL (tar.gz):

```
https://github.com/julioliraup/Antiphishing/raw/refs/heads/main/antiphishing.tar.gz
```
Dot rules file:

```
https://github.com/julioliraup/Antiphishing/raw/refs/heads/main/antiphishing.rules
```

# 🛡️ NRD Threat Intelligence

Antiphishing now includes a **Newly Registered Domains (NRD)** analysis layer focused on proactive phishing infrastructure detection.

The pipeline analyzes newly registered domains with observed DNS resolution/activity through public recursive DNS resolvers.

The analysis generates **more than 1.5 million possible domain combinations** for inspection, using techniques associated with:

- Typosquatting
- Homoglyph detection
- Brand impersonation
- High-risk phishing terminology

The generated combinations are analyzed to identify domains that present suspicious characteristics.

Domains classified as suspicious by the analysis pipeline are automatically incorporated into the Antiphishing intelligence dataset and can become detection indicators for **DNS and TLS/SNI traffic in Suricata**.

Antiphishing Threat Intel are added to the file:
```
nrd_suspicious_domains.txt
```

Obs.: **NRD threat intelligence rules consider the domains suspicious; there is no validated confirmation that they are malicious, otherwise there is a high chance of false positives.**

# Updates & Automation
Our ruleset is updated dynamically every ~6 hours to track emerging phishing vectors. 
- **SID Range:** `6000000` - `6100000` (Carefully assigned to prevent conflicts with other [rulesets](https://sidallocation.org/))  .
- **Format:** Fully compatible with `suricata-update`.

---

## 🙏 Acknowledgments

A special and sincere thanks to [@antixmars](https://github.com/antixmars) for their contribution to this project.
Good work deserves to be recognized — and yours was both timely and valuable. Thank you.

---

## 💛 Support This Project

This project is maintained by a single person, driven by the belief that effective phishing detection should be accessible to everyone — from homelab enthusiasts to enterprise security teams.

Building and sustaining this kind of threat intelligence infrastructure takes real time and real resources: pipeline maintenance, rule engineering, dataset curation, false positive management, and continuous research into emerging phishing tactics.

If this project has been useful to you — whether it protected a network, helped a student learn, or saved an analyst time — consider supporting it. Even a small contribution makes it possible to keep the lights on.

There is no subscription, no paywall, and no premium tier. Everything here is free. A donation is simply an acknowledgment that this work has value.

#### 🇧🇷 Doação via PIX (Brasil)
- **Chave PIX:** `08650081401`
- **Beneficiário:** Júlio Lira

#### 🌐 GitHub Sponsors (International)
For recurring support or one-time contributions: [github.com/sponsors/julioliraup](https://github.com/sponsors/julioliraup)

---

## Contact & False Positives

If you encounter any false positives, have suggestions, or want to discuss corporate partnerships:
- **Email:** [jul10l1r4@disroot.org](mailto:jul10l1r4@disroot.org)
- **Issues:** Please open a GitHub Issue for rule adjustments.
