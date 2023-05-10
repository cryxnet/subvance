import sys
import argparse
import requests
import dns.resolver
import ssl
import OpenSSL
from urllib.parse import urlparse
from prettytable import PrettyTable
import os
from bs4 import BeautifulSoup
import logging
from urllib.parse import quote

header = r"""
 _______           ______            _______  _        _______  _______ 
(  ____ \|\     /|(  ___ \ |\     /|(  ___  )( (    /|(  ____ \(  ____ \
| (    \/| )   ( || (   ) )| )   ( || (   ) ||  \  ( || (    \/| (    \/
| (_____ | |   | || (__/ / | |   | || (___) ||   \ | || |      | (__    
(_____  )| |   | ||  __ (  ( (   ) )|  ___  || (\ \) || |      |  __)   
      ) || |   | || (  \ \  \ \_/ / | (   ) || | \   || |      | (      
/\____) || (___) || )___) )  \   /  | )   ( || )  \  || (____/\| (____/\
\_______)(_______)|/ \___/    \_/   |/     \||/    )_)(_______/(_______/

     ╭――――――――――――――――――――――――――――――――――――――――――――――――――――――――╮        
     │                Subdomain Discovery Tool                │        
     │――――――――――――――――――――――――――――――――――――――――――――――――――――――――│
     │     By: cryxnet                                        │
     │     Repository: https://github.com/cryxnet/subvance    │ 
     ╰――――――――――――――――――――――――――――――――――――――――――――――――――――――――╯
"""

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Create a file handler with DEBUG level
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Create a stream handler with INFO level
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
stream_handler.setFormatter(logging.Formatter('%(message)s'))

# Add the handlers to the root logger
logger = logging.getLogger('')
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

def cert_fingerprint(domain):
    logging.info(f"Performing certificate fingerprinting for domain: {domain}")
    
    ct_url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(ct_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"})
    subdomains = []
    if response.status_code == 200:
        for cert in response.json():
            subdomain = cert['name_value']
            if subdomain not in subdomains:
                subdomains.append(subdomain)
                logging.debug(f"New domain found with certificate fingerprinting technique: {domain}")
    else:
        logger.error(f"Failed certificate fingerprinting for domain: {domain} with status code: {response.status_code}")
    
    return subdomains

def brute_force(domain, wordlist_file):
    logging.info(f"Performing bruteforce for domain: {domain}")

    subdomains = []
    with open(wordlist_file) as f:
        wordlist = f.read().splitlines()
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            dns.resolver.query(subdomain, 'A')
            subdomains.append(subdomain)
            logging.debug(f"New domain found with bruteforce technique: {domain}")
        except:
            pass
    return subdomains

def google_dorks(domain, limit=5):
    logging.info(f"Performing google dorks for domain: {domain}")
    
    page = 0
    result_urls = []
    headers = {"Cookie": "CONSENT=YES+cb.20220404-01-p0.en-GB+FX+142", 
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
               "referer": "https://www.google.com/"
            }
    google_search_base_query = "https://www.google.com/search?q="
    
    while page < limit:
        
        params = f"site:*.{domain}"
        
        encoded_params = quote(params)
        
        query = google_search_base_query + encoded_params + f"&start={page*10}"
    
        response = requests.get(query, headers=headers)
        soup = BeautifulSoup(response.content, "html.parser")
        
        if "Our systems have detected unusual traffic from your computer network. This page checks to see if it's really you sending the requests, and not a robot." in soup.text:
            logger.critical("Google detected suspicious traffic, bot protection detected you. Please try again later.")
            raise Exception("Google detected suspicious traffic, bot protection detected you. Please try again later.")
        
        
        for g in soup.find_all('div', class_='g'):
            anchors = g.find_all('a')
          
            if anchors:
                url = anchors[0]['href']
                parsed_url = urlparse(url)
                parsed_domain = parsed_url.netloc
                result_urls.append(parsed_domain)
                logging.debug(f"New domain found in google dorks: {parsed_domain}")
                if limit < page:
                    break
             
        page += 1
      
    return result_urls

def passive_subdomain_recon(domain):
    logging.info(f"Performing passive techniques for domain: {domain}")
    
    subdomains = []
    subdomains += cert_fingerprint(domain)
    subdomains += google_dorks(domain)
    return subdomains

def active_subdomain_recon(domain):
    logging.info(f"Performing active techniques for domain: {domain}")

    subdomains = []
    subdomains += brute_force(domain)

def main():
    parser = argparse.ArgumentParser(description='Discover subdomains for a given domain.')
    parser.add_argument('domain', type=str, help='Target domain to enumerate subdomains for.')
    parser.add_argument('-o', '--output', type=str, help='Output file name to write the subdomains to.')
    parser.add_argument('--cert-fingerprint', action='store_true', help='Use Certificate Transparency Logs to discover subdomains.')
    parser.add_argument('--google-dorks', action='store_true', help='Use Google dorks to discover subdomains.')
    parser.add_argument('--brute-force', action='store_true', help='Use brute-forcing to discover subdomains.')
    parser.add_argument('--passive', action='store_true', help='Use passive subdomain discovery.')
    parser.add_argument('--active', action='store_true', help='Use active subdomain discovery.')
    parser.add_argument('--wordlist', type=str, help='Wordlist file path to use for brute-forcing.')
    parser.add_argument('--all', action='store_true', help='Use every technique to discover subdomains.')
    args = parser.parse_args()
    
    print(header)

    subdomains = []
    domain = args.domain

    if args.cert_fingerprint:
        subdomains += cert_fingerprint(domain)
        
    if args.google_dorks:
        subdomains += google_dorks(domain)

    if args.brute_force:
        if args.wordlist:
            subdomains += brute_force(domain, args.wordlist)
        else:
            print("Error: Please specify a wordlist file path using the --wordlist flag when using brute-force.")
            sys.exit(1)

    if args.passive:
        subdomains += passive_subdomain_recon(domain)

    if args.active:
        if args.wordlist:
            subdomains += active_subdomain_recon(domain, args.wordlist)
        else:
            print("Error: Please specify a wordlist file path using the --wordlist flag.")
            sys.exit(1)
    
    if args.all:
        if args.wordlist:
            subdomains += active_subdomain_recon(domain, args.wordlist)
            subdomains += passive_subdomain_recon(domain)
        else:
            print("Error: Please specify a wordlist file path using the --wordlist flag.")
            sys.exit(1)

    subdomains = list(set(subdomains))

    logging.info("Finished with discovery, " + ' '.join(sys.argv))
    logging.debug("Subdomains: %s" % subdomains)
    
    if args.output:
        with open(args.output, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
            f.close()
        print("Successfully wrote output to {}".format(args.output))
    else:
        print(f"""
Result of {' '.join(sys.argv)}
----------------------------------------------------
""" )
        table = PrettyTable(["#", "Subdomain"])
        for i, subdomain in enumerate(subdomains):
            table.add_row([i+1, subdomain])
        print(table)
       
if __name__ == '__main__':
    main()