import requests

# URL da API do PhishStats
phishstats_url = "https://phishstats.info/phish_score.csv"
openphish_url = "https://openphish.com/feed.txt"
output_file = "antiphishing.rules"

def fetch_phishing_urls(url):
    response = requests.get(url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        return lines[1:]
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def create_suricata_rules(urls, reference):
    rules = []
    sid = 6000000 
    for url in urls:
        parts = ""
        rule = ""
        rule_tls = ""
        # Phishstats use csv format
        if reference == "phishstats.info": 
            parts = url.split(",")
        else:
            parts = url
        if len(parts) > 0:
            if reference == "phishstats.info":
                phish_url = parts[2].split('//')[1][0:-1]
            else:
                phish_url = parts.split('//')[1][0:]

            new_phish_url = phish_url.replace('.','[.]')

            if "/" not in phish_url[0:-1]:
                rule = f'alert dns $HOME_NET any -> any any (msg:"AT Related Malicious Domain ({new_phish_url}) in DNS Lookup"; dns.query; content:"{phish_url[0:-1]}"; isdataat:!1,relative; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; signature_severity Major;)'
                sid += 1
                rule_tls = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"AT Related Malicious Domain ({new_phish_url}) in TLS SNI"; flow:established,to_server; tls.sni; dotprefix; content:".{phish_url[0:-1]}"; endswith; fast_pattern; reference:url,github.com/julioliraup/Antiphishing; reference:url,{reference}; classtype:social-engineering; sid:{sid}; rev:1; signature_severity Major;)'
            else:
                domain = phish_url.split('/')[0]
                path = phish_url.split(domain)[1]
                rule = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:to_server,established; content:"GET {path}"; http_uri; fast_pattern:only; content:"Host|3A| {domain}"; http_header; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; signature_severity Major;)'

            rules.append(rule)
            if len(rule_tls) > 5: rules.append(rule_tls)
            sid += 1  # Incrementa o SID para a próxima regra
    return rules

def main():
    rules = []
    rule = ""
    phishstats = create_suricata_rules(fetch_phishing_urls(phishstats_url)[8:], 'phishstats.info')
    openphish = create_suricata_rules(fetch_phishing_urls(openphish_url), 'openphish.com')
    rules = phishstats
    rules += openphish

    with open(output_file, "r+") as f:
        content_file = f.read()
        for rule in rules:
            if rule[0:130] not in content_file:
                f.write(rule + "\n")
    print(f"Rulesets: {output_file}")

if __name__ == "__main__":
    main()
