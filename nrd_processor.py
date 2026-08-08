import requests
from base64 import b64encode
import os
import re
import dnstwist
import tldextract

NRD_FEED_URL = "https://raw.githubusercontent.com/cbuijs/nrd/main/nrd-1d.domains.list"
NRD_SUSPICIOUS_FILE = "nrd_suspicious_domains.txt"
PHISHING_LST_FILE = "phishing.lst"

TARGET_BRAND_DOMAINS = [
    "chase.com", "bankofamerica.com", "hsbc.com", "santander.com", "wellsfargo.com",
    "revolut.com", "wise.com", "barclays.com", "citibank.com", "nubank.com.br",
    "bradesco.com.br", "itau.com.br", "caixa.gov.br", "amazon.com", "ebay.com",
    "paypal.com", "mercadolibre.com", "mercadopago.com", "stripe.com", "shopify.com",
    "apple.com", "google.com", "microsoft.com", "meta.com", "facebook.com",
    "instagram.com", "whatsapp.com", "netflix.com", "adobe.com", "salesforce.com",
    "dropbox.com", "binance.com", "coinbase.com", "metamask.io", "trustwallet.com",
    "crypto.com", "ledger.com", "telegram.org", "discord.com", "linkedin.com", "tiktok.com"
]

TARGET_BRAND_NAMES = [
    "chase", "bankofamerica", "hsbc", "santander", "wellsfargo", "revolut", "wise",
    "barclays", "citibank", "nubank", "bradesco", "itau", "caixa", "amazon", "ebay",
    "paypal", "mercadolibre", "mercadopago", "stripe", "shopify", "apple", "google",
    "microsoft", "meta", "facebook", "instagram", "whatsapp", "netflix", "adobe",
    "salesforce", "dropbox", "binance", "coinbase", "metamask", "trustwallet",
    "cryptocom", "ledger", "telegram", "discord", "linkedin", "tiktok", "magazineluiza",
    "bancodobrasil", "pagseguro"
]

MULTILANGUAGE_KEYWORDS = [
    "login", "signin", "verify", "account", "security", "update", "support",
    "billing", "secure", "auth", "portal", "alert", "restore", "bank", "wallet",
    "acesso", "atendimento", "seguranca", "recuperar", "confirmar", "fatura",
    "pix", "banco", "atualizacao", "cadastrar", "cartao", "bloqueio", "acceso",
    "seguridad", "cuenta", "validar", "soporte", "clave", "verificar", "ingreso",
    "konto", "securite", "verification", "anmelden", "connexion"
]

def extract_registered_domain(domain):
    domain = domain.lower().strip()
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}", extracted.domain
    return domain, domain.split('.')[0]

def build_dnstwist_permutation_set():
    permutations = set()
    print(f"[+] Generating dnstwist permutations for {len(TARGET_BRAND_DOMAINS)} target brand domains...")
    for brand_domain in TARGET_BRAND_DOMAINS:
        try:
            fuzzer = dnstwist.Fuzzer(brand_domain)
            fuzzer.generate()
            for entry in fuzzer.domains:
                if isinstance(entry, dict):
                    domain_name = entry.get("domain") or entry.get("domain-name")
                elif isinstance(entry, str):
                    domain_name = entry
                else:
                    domain_name = None
                if domain_name:
                    permutations.add(domain_name.lower())
        except Exception as error:
            print(f"[!] dnstwist error processing {brand_domain}: {error}")
    print(f"[+] Total dnstwist permutations generated: {len(permutations)}")
    return permutations

def fetch_nrd_feed():
    print(f"[+] Fetching daily NRD feed from {NRD_FEED_URL}...")
    try:
        response = requests.get(NRD_FEED_URL, timeout=30)
        if response.status_code == 200:
            lines = [line.strip().lower() for line in response.text.splitlines() if line.strip()]
            print(f"[+] Successfully fetched {len(lines)} NRD records.")
            return lines
        else:
            print(f"[!] Failed to fetch NRD feed. HTTP status: {response.status_code}")
            return []
    except Exception as error:
        print(f"[!] Exception fetching NRD feed: {error}")
        return []

def evaluate_nrd_domain(domain, dnstwist_permutations):
    registered_domain, brand_part = extract_registered_domain(domain)
    
    if registered_domain in dnstwist_permutations or domain in dnstwist_permutations:
        return True

    for brand in TARGET_BRAND_NAMES:
        if brand in brand_part:
            for keyword in MULTILANGUAGE_KEYWORDS:
                if keyword in brand_part:
                    return True
            if re.search(fr"{brand}[-\d]|[-\d]{brand}", brand_part):
                return True
        
        normalized_name = brand_part.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('4', 'a').replace('5', 's')
        if brand in normalized_name and brand not in brand_part:
            return True

    return False

def process_nrd_list():
    nrd_domains = fetch_nrd_feed()
    if not nrd_domains:
        return

    nrd_domains = list(dict.fromkeys(nrd_domains))

    dnstwist_permutations = build_dnstwist_permutation_set()

    existing_suspicious = set()
    if os.path.exists(NRD_SUSPICIOUS_FILE):
        with open(NRD_SUSPICIOUS_FILE, "r") as file_handle:
            existing_suspicious = set(line.strip().lower() for line in file_handle if line.strip())

    existing_phishing_base64 = set()
    if os.path.exists(PHISHING_LST_FILE):
        with open(PHISHING_LST_FILE, "r") as file_handle:
            existing_phishing_base64 = set(line.strip() for line in file_handle if line.strip())

    new_suspicious = []
    print(f"[+] Analyzing {len(nrd_domains)} unique NRD domains for phishing structures...")

    for domain in nrd_domains:
        if domain not in existing_suspicious and domain not in new_suspicious:
            if evaluate_nrd_domain(domain, dnstwist_permutations):
                new_suspicious.append(domain)

    print(f"[+] Detected {len(new_suspicious)} new suspicious NRD domains.")

    if new_suspicious:
        with open(NRD_SUSPICIOUS_FILE, "a") as file_handle:
            for domain in new_suspicious:
                if domain not in existing_suspicious:
                    file_handle.write(f"{domain}\n")
                    existing_suspicious.add(domain)

        with open(PHISHING_LST_FILE, "a") as file_handle:
            for domain in new_suspicious:
                encoded_domain = b64encode(domain.encode()).decode()
                if encoded_domain not in existing_phishing_base64:
                    file_handle.write(f"{encoded_domain}\n")
                    existing_phishing_base64.add(encoded_domain)

        print(f"[✓] Processed NRD entries successfully saved to '{NRD_SUSPICIOUS_FILE}' and '{PHISHING_LST_FILE}'.")
    else:
        print("[✓] No new suspicious NRD domains detected.")

if __name__ == "__main__":
    process_nrd_list()
