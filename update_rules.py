import requests
from datetime import datetime

phishstats_url = "https://phishstats.info/phish_score.csv"
openphish_url = "https://openphish.com/feed.txt"
output_file = "antiphishing.rules"
sid_file = "sid_tracker.txt"

def fetch_phishing_urls(url):
    response = requests.get(url)
    if response.status_code == 200:
        lines = response.text.splitlines()
        return lines[1:]
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def get_last_sid():
    try:
        with open(sid_file, "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 6000000 
    except ValueError:
        return 6000000 

def update_last_sid(sid):
    with open(sid_file, "w") as f:
        f.write(str(sid))

def create_suricata_rules(urls, reference, last_sid):
    rules = []
    sid = last_sid
    for url in urls:
        parts = ""
        rule = ""
        rule_tls = ""

        if reference == "phishstats.info": 
            parts = url.split(",")
        else:
            parts = url
        if len(parts) > 0:
            current_data = datetime.now().strftime("%Y_%m_%d")
            if reference == "phishstats.info":
                phish_url = parts[2].split('//')[1][0:-1]
            else:
                phish_url = parts.split('//')[1][0:-1]

            new_phish_url = phish_url.replace('.',' .')[0:-1]

            if "/" not in phish_url[0:-1]:
                rule = f'alert dns $HOME_NET any -> any any (msg:"AT Related Malicious Domain ({new_phish_url}) in DNS Lookup"; dns.query; bsize:{len(phish_url)+1}; content:"{phish_url}"; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)'
                sid += 1
                rule_tls = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"AT Related Malicious Domain ({new_phish_url}) in TLS SNI"; flow:established,to_server; tls.sni; dotprefix; content:".{phish_url}"; endswith; fast_pattern; reference:url,github.com/julioliraup/Antiphishing; reference:url,{reference}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)'
            else:
                domain = phish_url.split('/')[0]
                path = phish_url.split(domain)[1]
                rule = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain}"; bsize:{len(domain)+1}; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)'

            rules.append(rule)
            if len(rule_tls) > 5: rules.append(rule_tls)
            sid += 1
    return rules, sid

def main():
    rules = []
    rule = ""
    last_sid = get_last_sid()
    
    phishstats, last_sid = create_suricata_rules(fetch_phishing_urls(phishstats_url)[8:], 'phishstats.info', last_sid)
    openphish, last_sid = create_suricata_rules(fetch_phishing_urls(openphish_url), 'openphish.com', last_sid)
    
    rules = phishstats + openphish
    
    with open(output_file, "r+") as f:
        content_file = f.read()
        for rule in rules:
            if rule[0:130] not in content_file:
                f.write(rule + "\n")
    
    update_last_sid(last_sid)
    print(f"Rulesets: {output_file}")

if __name__ == "__main__":
    main()

