import requests
from re import search
from base64 import b64encode, b64decode
from datetime import datetime
import os

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
            domain = b64encode(domain.encode()).decode()
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
                path.replace(';', '|3b|')

                if domain not in rule or path not in rule:
                    rule = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"{path}"; startswith; fast_pattern; http.host; bsize:{len(domain)+1}; content:"{domain}"; reference:url,{reference}; reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)'
                    sid += 1

            rules.append(rule)
            if len(rule_tls) > 5: rules.append(rule_tls)
    return rules, sid

def check_existing_urls():
    valid_rules = []
    removed_sids = []
    
    try:
        with open(phishing_list, "r") as f:
            domains = f.readlines()
        
        with open(output_file, "r") as f:
            rules = f.readlines()
        
        for domain in domains:
            try:
                url = "http://" + b64decode(domain.strip()).decode()
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    continue
            except:
                domain_decoded = b64decode(domain.strip()).decode()
                for rule in rules:
                    if domain_decoded in rule:
                        rules.remove(rule)
                        match = search(r'sid:(\d+);', rule)
                        if match:
                            removed_sids.append(int(match.group(1)))
        
        return rules, removed_sids
    except FileNotFoundError:
        return [], []

def create_new_ruleset(rules, available_sids):
    sid_counter = 6000000
    new_rules = []
    sid_exceeded = False
    
    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    header = """# Suricata Antiphishing rules
# Created by github.com/julioliraup/Antiphishing
# Last updated: {} GMT{}
# SID range: 6000000-6100000
#
""".format(formatted_time, gmt_offset)
    
    new_rules.append(header)
    
    for rule in rules:
        if 'sid:' in rule:
            old_sid = int(search(r'sid:(\d+);', rule).group(1))
            if available_sids:
                new_sid = available_sids.pop(0)
            else:
                new_sid = sid_counter
                sid_counter += 1
                
            if new_sid > 6100000:
                sid_exceeded = True
            
            new_rule = rule.replace(f'sid:{old_sid};', f'sid:{new_sid};')
            new_rules.append(new_rule)
    
    return new_rules, sid_exceeded

def main():
    existing_rules, available_sids = check_existing_urls()
    temp_output_file = output_file + ".temp"
    rules = []
    last_sid = 6000000
    
    phishstats, last_sid = create_suricata_rules(fetch_phishing_urls(phishstats_url)[8:], 'phishstats.info', last_sid)
    openphish, last_sid = create_suricata_rules(fetch_phishing_urls(openphish_url), 'openphish.com', last_sid)
    
    all_rules = list(filter(None, existing_rules + phishstats + openphish))
    new_rules, sid_exceeded = create_new_ruleset(all_rules, available_sids)
    
    with open(temp_output_file, "w") as f:
        for rule in new_rules:
            f.write(rule)
    
    os.replace(temp_output_file, output_file)
    update_last_sid()
    
    print(f"Rulesets: {output_file}")
    
    if sid_exceeded:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

if __name__ == "__main__":
    main()

