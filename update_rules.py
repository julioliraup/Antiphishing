import requests
from datetime import datetime
from base64 import b64encode

phishstats_url = "https://api.phishstats.info/api/phishing?_sort=-id"
openphish_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
output_file = "antiphishing.rules"
phishing_list = "phishing.lst"
sid_file = "sid_tracker.txt"

banner = """\033[32m
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡿⠿⠛⢉⣀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠟⢁⣤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠃⣰⣿\033[41;37m ANTIPHISHING \033[0;32m⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⠀⢿⣿⣿⣿⣿⣿⡏⠀⢠⣾⣿⣿⡆⠀⠸⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿
⣿⣧⠈⠻⣿⣿⣿⣿⣷⠾⠻⣿⣿⣿⠇⠀⢰⣿⣿⣿⣿⣿⣷⠀⠙⢿⣿⣿⣿⣿
⣿⣿⣿⣦⣄⣈⣉⣀⣤⣴⡞⠋⠉⠁⠀⠠⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠻⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⠀⠀⠘⣿⣿⣿⣿⣿⣿⡇⠀⡀⠀⠹⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠈⢿⣿⣿⣿⣿⣧⣾⣿⡄⠀⢹⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠈⢿⣿⣿⣿⣿⣿⣿⠇⠀⢸⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠻⢿⣿⣿⡿⠋⠀⠀⣼⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣶⣾⣿⣿⣿⣿
SID range: 6000000-6100000 ⣿⣿⣿
\033[0m
https://github.com/julioliraup/Antiphishing
"""

def fetch_phishing_urls(url):
    response = requests.get(url)
    if response.status_code == 200:
        if "phishstats" in url:
            data = response.json()
            return [item.get('url') for item in data if item.get('url')]
        else:
            return response.text.splitlines()
    else:
        raise Exception(f"Failed to fetch data: {response.status_code}")

def get_last_sid():
    try:
        with open(sid_file, "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 6000001  # Começando de 6000001 pois 6000000 é reservado para regra DNS
    except ValueError:
        return 6000001

def is_domain_in_rules(domain, rules):
    # Verifica se o domínio já existe nas regras HTTP
    for rule in rules:
        if 'content:"' + domain + '"' in rule:
            return True
    return False

def is_domain_in_phishing_list(domain):
    try:
        with open(phishing_list, "r") as f:
            domains = f.readlines()
            encoded_domain = b64encode(domain.encode()).decode()
            return encoded_domain + "\n" in domains
    except FileNotFoundError:
        return False

def update_dataset(domain, rules):
    # Verifica se o domínio já existe nas regras ou na lista
    if not is_domain_in_rules(domain, rules) and not is_domain_in_phishing_list(domain):
        with open(phishing_list, "a") as f:
            encoded_domain = b64encode(domain.encode()).decode()
            f.write(encoded_domain + "\n")

def create_suricata_rules(urls, reference, last_sid, existing_rules):
    rules = []
    sid = last_sid
    urls = list(set(urls))
    total = len(urls)
    
    for i, url in enumerate(urls, 1):
        rule = ""

        if url:
            print(f"\r\033[K[{i}/{total}] Processing {reference}: {url[:60]}", end="")
            current_data = datetime.now().strftime("%Y_%m_%d")
            
            if "://" in url:
                phish_url = url.split("://", 1)[1]
            else:
                phish_url = url

            new_phish_url = phish_url.replace('.',' .')
            new_phish_url = phish_url.replace(';','\;')

            if "/" not in phish_url:
                # Se for apenas domínio, adiciona à lista de phishing
                domain = phish_url
                if not is_domain_in_rules(domain, existing_rules):
                    update_dataset(domain, existing_rules)
            else:
                domain = phish_url.split('/')[0]
                path = phish_url.split(domain, 1)[1]
                path = path.replace(';', '|3b|')

                # Verifica se o domínio/path já existe nas regras
                if not is_domain_in_rules(domain, existing_rules):
                    rule = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain.lower()}"; endswith; reference:url,{reference}; reference:url,julioliraup.github.io/ET/signature.html?sid={sid}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)\n'
                    sid += 1

            if rule:
                rules.append(rule)
                
    print()  # Quebra a linha após o loop
    return rules, sid

def main():
    print(banner)
    print("\nStarting Antiphishing Update...\n")
    # Lê as regras existentes
    try:
        with open(output_file, "r") as f:
            existing_rules = f.readlines()
    except FileNotFoundError:
        existing_rules = []

    last_sid = get_last_sid()
    
    # Cria novas regras
    print(f"Fetching URLs from {phishstats_url}...")
    phishstats_urls = fetch_phishing_urls(phishstats_url)
    phishstats, last_sid = create_suricata_rules(
        phishstats_urls, 
        'phishstats.info', 
        last_sid,
        existing_rules
    )
    
    print(f"\nFetching URLs from {openphish_url}...")
    openphish_urls = fetch_phishing_urls(openphish_url)
    openphish, last_sid = create_suricata_rules(
        openphish_urls, 
        'openphish.com', 
        last_sid,
        existing_rules
    )

    # Mantém a regra DNS fixa e adiciona as novas regras
    domain_rule = 'alert dns $HOME_NET any -> any any (msg:"AT DNS query to suspicious domain - Phishing"; dns.query; dataset:isset,phishing_domains,type string; reference:url,github.com/julioliraup/Antiphishing; classtype:suspicious-traffic; sid:6000000; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n\nalert tls $HOME_NET any -> any any (msg:"AT TLS SNI to suspicious domain - Phishing"; tls.sni; dataset:isset,phishing_domains,type string; reference:url,github.com/julioliraup/Antiphishing; reference:url,julioliraup.github.io/ET/signature.html?sid=6000001; classtype:social-engineering; sid:6000001; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)'
    
    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# Suricata Antiphishing rules
# Created by github.com/julioliraup/Antiphishing
# Last updated: {formatted_time} GMT{gmt_offset}
# SID range: 6000000-6100000
#
"""

    # Filtra as regras antigas para manter apenas as regras HTTP (removendo cabeçalhos e a regra DNS antiga)
    old_rules = [r for r in existing_rules if r.strip().startswith("alert http")]

    # Combina todas as regras
    all_rules = [header, domain_rule] + old_rules + phishstats + openphish

    # Escreve as regras no arquivo
    with open(output_file, "w") as f:
        for rule in all_rules:
            f.write(rule)

    # Atualiza o último SID
    with open(sid_file, "w") as f:
        f.write(str(last_sid))

    print(f"Rulesets updated: {output_file}")
    if last_sid > 6100000:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

if __name__ == "__main__":
    main()

