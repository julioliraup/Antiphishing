![Antiphishing logo](img/antiphishing.png)
> Protect against phishing attacks

# Functionality

This rule is built using malicious URLs and domains involved in phishing attacks. We utilize some community APIs to construct these rules, and with them, we create TLS, DNS, and HTTP rules.

Our sources:
1. [Phishstats](https://phishstats.info)
2. [Openphish](https://openphish.com/)

# Updates
Our rule updates hourly and includes SIDs that take other rulesets into consideration. Range: 6000000 - 6100000
