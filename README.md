![Antiphishing logo](img/antiphishing.png)
> Protect against phishing attacks

# Functionality

This rule is built using malicious URLs and domains involved in phishing attacks. We utilize some community APIs to construct these rules, and with them, we create TLS, DNS, and HTTP rules.

Our sources:
1. [Phishstats](https://phishstats.info)
2. [Openphish](https://openphish.com/)

# Use
After download `antiphishing.rules` and `phishing.lst` move for `/etc/suricata` or you directory rulesets.
Now restart suricata daemon.

# Updates
Our rule updates frequently and includes SIDs that take other rulesets into consideration. Range: 6000000 - 6100000

### How to Donate
Currently, we lack the dedicated servers required to generate these rules. Additionally, our lookup portal—[julioliraup/AT](/julioliraup/AT)—which could enhance our threat intelligence data, faces performance limitations due to a lack of resources for active software licenses.

You can support us directly via PIX (Brazil):

- **PIX Key**: `08650081401`

### Contact

If you have any questions, suggestions, or would like to discuss other ways to collaborate, please feel free to reach out via email:
- **Email**: [jul10l1r4@disroot.org](mailto:jul10l1r4@disroot.org)

---
*Thank you for supporting open-source security!*
