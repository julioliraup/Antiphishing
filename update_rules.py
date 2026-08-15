import requests
from datetime import datetime
from base64 import b64encode
import hashlib
import sys
import json
import os
import re
from nrd_processor import process_nrd_list

phishstats_url = "https://api.phishstats.info/api/phishing?_sort=-id"
openphish_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
index_json_url = "https://julioliraup.github.io/AT/db/index.json"
output_file = "antiphishing.rules"
phishing_list = "phishing.lst"
phishing_ip_list = "phishing_ips.lst"
sid_file = "sid_tracker.txt"
index_file = "index.json"

ipv4_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# Regras de dataset (SIDs reservados 6000000-6000002). Definidas em um único
# lugar para que os dois caminhos de geração não saiam de sincronia.
dataset_rules = (
    'alert dns $HOME_NET any -> any any (msg:"AT DNS query to suspicious domain - Phishing"; '
    'dns.query; dataset:isset,phishing_domains,type string,load phishing.lst; '
    'reference:url,github.com/julioliraup/Antiphishing; classtype:social-engineering; '
    'sid:6000000; rev:1; metadata: signature_severity Major, created_et 2025_02_19;)\n'
    '\n'
    'alert tls $HOME_NET any -> any any (msg:"AT TLS SNI to suspicious domain - Phishing"; '
    'tls.sni; dataset:isset,phishing_domains,type string,load phishing.lst; '
    'reference:url,github.com/julioliraup/Antiphishing; '
    'reference:url,julioliraup.github.io/AT/signature.html?sid=6000001; '
    'classtype:social-engineering; sid:6000001; rev:1; '
    'metadata: signature_severity Major, created_et 2025_02_19;)\n'
    '\n'
    'alert ip $HOME_NET any -> any any (msg:"AT IP reputation - Phishing"; '
    'ip.dst; dataset:isset,phishing_ips,type ipv4,load phishing_ips.lst; '
    'reference:url,github.com/julioliraup/Antiphishing; '
    'reference:url,julioliraup.github.io/AT/signature.html?sid=6000002; '
    'classtype:social-engineering; sid:6000002; rev:1; '
    'metadata: signature_severity Major, created_et 2026_08_14;)\n'
)

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
        return 6000003  # 6000000-6000002 reservados para as regras de dataset (DNS, TLS, IP)
    except ValueError:
        return 6000003

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

def is_ipv4(value):
    # Valida o formato e o intervalo de cada octeto
    if not ipv4_pattern.match(value):
        return False
    return all(0 <= int(octet) <= 255 for octet in value.split('.'))

def is_ip_in_phishing_ip_list(ip_address):
    try:
        with open(phishing_ip_list, "r") as f:
            return ip_address + "\n" in f.readlines()
    except FileNotFoundError:
        return False

def update_ip_dataset(ip_address):
    # Datasets do tipo ipv4 usam texto puro, não base64
    if not is_ip_in_phishing_ip_list(ip_address):
        with open(phishing_ip_list, "a") as f:
            f.write(ip_address + "\n")

def update_dataset(domain, rules):
    # Um literal de IP nunca casa com dns.query nem com tls.sni,
    # então vai para o dataset ipv4 usado pela regra de reputação
    if is_ipv4(domain):
        update_ip_dataset(domain)
        return

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
                    rule = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain.lower()}"; endswith; reference:url,{reference}; reference:url,julioliraup.github.io/AT/signature.html?sid={sid}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)\n'
                    sid += 1

            if rule:
                rules.append(rule)
                
    print()  # Quebra a linha após o loop
    return rules, sid

def update_from_index():
    print(banner)
    print(f"\nFetching index.json from {index_json_url}...")
    response = requests.get(index_json_url)
    if response.status_code == 200:
        with open(index_file, "w") as f:
            f.write(response.text)
    else:
        raise Exception(f"Failed to fetch index: {response.status_code}")

    with open(index_file, "r") as f:
        data = json.load(f)

    try:
        with open(output_file, "r") as f:
            existing_rules = f.readlines()
    except FileNotFoundError:
        existing_rules = []

    rules_by_sid = {}
    rules_by_msg = {}
    for rule in existing_rules:
        if not rule.startswith("alert http"):
            continue
        m_sid = re.search(r"sid:(\d+);", rule)
        if m_sid:
            rules_by_sid[int(m_sid.group(1))] = rule
        m_msg = re.search(r'msg:"([^"]+)";', rule)
        if m_msg:
            rules_by_msg[m_msg.group(1)] = rule

    active_items = [item for item in data if item.get("rule_status") == "active" and item.get("protocol") == "http"]
    total = len(active_items)

    rules = []
    sid = 6000003
    seen_hosts = {}   # host -> primeiro SID que o registrou
    duplicates_skipped = 0

    for i, item in enumerate(active_items, 1):
        item_sid = item.get("sid")
        msg = item.get("name", "")
        print(f"\r\033[K[{i}/{total}] Processing active rule: {msg[:60]}", end="")

        rule_str = rules_by_sid.get(item_sid) or rules_by_msg.get(msg)
        if rule_str:
            rule_str = re.sub(r"sid:\d+;", f"sid:{sid};", rule_str)
            rule_str = re.sub(r"signature\.html\?sid=\d+", f"signature.html?sid={sid}", rule_str)
        else:
            m = re.match(r"^AT related malicious URL \((.*)\)$", msg)
            if m:
                new_phish_url = m.group(1)
                phish_url = new_phish_url.replace(" .", ".").replace(r"\;", ";")
                if "/" in phish_url:
                    domain = phish_url.split("/")[0]
                    path = phish_url.split(domain, 1)[1].replace(";", "|3b|")
                else:
                    domain = phish_url
                    path = "/"
                current_data = datetime.now().strftime("%Y_%m_%d")
                rule_str = f'alert http $HOME_NET any -> any any (msg:"AT related malicious URL ({new_phish_url})"; flow:established,to_server; http.uri; content:"{path}"; startswith; fast_pattern; http.host; content:"{domain.lower()}"; endswith; reference:url,phishstats.info; reference:url,julioliraup.github.io/AT/signature.html?sid={sid}; classtype:social-engineering; sid:{sid}; rev:1; metadata: signature_severity Major, created_et {current_data};)\n'
            else:
                continue

        # --- deduplicação por http.host ---
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule_str)
        if m_host:
            host = m_host.group(1).lower()
            if host in seen_hosts:
                duplicates_skipped += 1
                print(f"\r\033[K  [SKIP] Duplicate host '{host}' (already mapped to SID {seen_hosts[host]}, current item SID {item_sid})")
                continue
            seen_hosts[host] = sid
        # ----------------------------------

        rules.append(rule_str)
        sid += 1

    print()
    if duplicates_skipped:
        print(f"Deduplication: {duplicates_skipped} rule(s) removed (same http.host already present).")

    domain_rule = dataset_rules

    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    header = f"""# Suricata Antiphishing rules
# Created by github.com/julioliraup/Antiphishing
# Last updated: {formatted_time} GMT{gmt_offset}
# SID range: 6000000-6100000
#
"""

    all_rules = [header, domain_rule] + rules

    with open(output_file, "w") as f:
        for rule in all_rules:
            f.write(rule)

    with open(output_file + ".md5", "w") as f:
        md5_hash = hashlib.md5(open(output_file, "rb").read()).hexdigest()
        f.write(md5_hash + "\n")

    with open(sid_file, "w") as f:
        f.write(str(sid))

    if os.path.exists(index_file):
        os.remove(index_file)

    print(f"Rulesets updated: {output_file}")
    if sid > 6100000:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

def main():
    if "--update" in sys.argv:
        update_from_index()
        return

    print(banner)
    print("\nStarting Antiphishing Update...\n")

    process_nrd_list()
    # Lê as regras existentes
    try:
        with open(output_file, "r") as f:
            existing_rules = f.readlines()
    except FileNotFoundError:
        existing_rules = []

    last_sid = get_last_sid()

    # Filtra as regras antigas para manter apenas as regras HTTP (removendo cabeçalhos e a regra DNS antiga)
    # Migração única: 6000000-6000002 agora são reservados para as regras de dataset,
    # então qualquer regra HTTP antiga nessa faixa é renumerada para evitar SID duplicado
    old_rules = []
    for rule in (r for r in existing_rules if r.strip().startswith("alert http")):
        m_old_sid = re.search(r"sid:(\d+);", rule)
        if m_old_sid and int(m_old_sid.group(1)) <= 6000002:
            rule = re.sub(r"sid:\d+;", f"sid:{last_sid};", rule)
            rule = re.sub(r"signature\.html\?sid=\d+", f"signature.html?sid={last_sid}", rule)
            last_sid += 1
        old_rules.append(rule)

    # Constrói índice de (host, path) das regras antigas para deduplicação
    # Isso impede que execuções normais após um --update recriem regras já existentes com SIDs novos
    existing_keys = set()
    for rule in old_rules:
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule)
        m_path = re.search(r'http\.uri; content:"([^"]+)"', rule)
        if m_host and m_path:
            existing_keys.add((m_host.group(1), m_path.group(1)))

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
    domain_rule = dataset_rules
    
    current_time = datetime.now()
    gmt_offset = current_time.astimezone().strftime('%z')
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    
    header = f"""# Suricata Antiphishing rules
# Created by github.com/julioliraup/Antiphishing
# Last updated: {formatted_time} GMT{gmt_offset}
# SID range: 6000000-6100000
#
"""

    # Remove das novas regras qualquer (host, path) que já exista nas antigas,
    # evitando duplicatas após um --update que renumerou os SIDs
    def is_new_rule_unique(rule):
        m_host = re.search(r'http\.host; content:"([^"]+)"', rule)
        m_path = re.search(r'http\.uri; content:"([^"]+)"', rule)
        if m_host and m_path:
            return (m_host.group(1), m_path.group(1)) not in existing_keys
        return True

    unique_phishstats = [r for r in phishstats if is_new_rule_unique(r)]
    unique_openphish  = [r for r in openphish  if is_new_rule_unique(r)]

    removed = len(phishstats) + len(openphish) - len(unique_phishstats) - len(unique_openphish)
    if removed:
        print(f"Deduplication: {removed} rule(s) skipped (domain+path already in existing rules).")

    # Combina todas as regras
    all_rules = [header, domain_rule] + old_rules + unique_phishstats + unique_openphish

    # Escreve as regras no arquivo
    with open(output_file, "w") as f:
        for rule in all_rules:
            f.write(rule)

    # Gera o hash MD5 do arquivo de regras para verificação de integridade (Suricata)
    with open(output_file, "rb") as f:
        md5_hash = hashlib.md5(f.read()).hexdigest()
    
    with open(output_file + ".md5", "w") as f:
        f.write(md5_hash + "\n")

    # Atualiza o último SID
    with open(sid_file, "w") as f:
        f.write(str(last_sid))

    print(f"Rulesets updated: {output_file}")
    if last_sid > 6100000:
        print("WARNING: SID range exceeded 6100000. Please consider adjusting the SID range.")

if __name__ == "__main__":
    main()

