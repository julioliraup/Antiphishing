import requests
from re import search
from datetime import datetime

phishstats_url = "https://phishstats.info/phish_score.csv"
openphish_url = "https://openphish.com/feed.txt"
output_file = "antiphishing.rules"
phishing_list = "phishing.lst"
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

def update_last_sid():
    sid = None
    with open(output_file, 'r') as file:
        file = file.readlines()
        last_line = file[-1].strip()
        match = search(r'sid:(\d+);', last_line)
        sid = match.group(1)

    with open(sid_file, "w") as f:
        f.write(str(sid))

def update_dataset(domain):
    with open(phishing_list, "r+") as f:
        content_file = f.read()
        if domain not in content_file:
            f.write(domain + "\n")

def create_suricata_rules(urls, reference, last_sid):
    rules = []
    sid = last_sid
    urls = list(set(urls))
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
                phish_url = parts[2].split('//')[1][0:-2]
            else:
                phish_url = parts.split('//')[1][0:-1]

            new_phish_url = phish_url.replace('.',' .')[0:-1]

            if "/" not in phish_url:
                update_dataset(phish_url) 
                sid += 1
            else:
                domain = phish_url.split('/')[0]
                path = phish_url.split(domain)[1]

                if domain not in rule or path not in rule:
                    rule = f'#alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"{path}"; startswith; fast_pattern; http.host; bsize:{len(domain)+1}; content:"{domain}"; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)'
                    sid += 1

            rules.append(rule)
            if len(rule_tls) > 5: rules.append(rule_tls)
    return rules, sid

def main():
    rules = []
    rule = ""
    last_sid = get_last_sid()
    
    phishstats, last_sid = create_suricata_rules(fetch_phishing_urls(phishstats_url)[8:], 'phishstats.info', last_sid)
    openphish, last_sid = create_suricata_rules(fetch_phishing_urls(openphish_url), 'openphish.com', last_sid)
    
    rules = list(filter(None, phishstats + openphish))
    
    with open(output_file, "r+") as f:
        content_file = f.read()
        for rule in rules:
            if rule[0:150] not in content_file:
                f.write(rule + "\n")
    
    update_last_sid()
    print(f"Rulesets: {output_file}")

if __name__ == "__main__":
    main()

