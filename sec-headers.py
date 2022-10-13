import requests
import argparse
from colorama import Fore, Back, Style, init
#from termcolor import colored

## OWASP Security Headers:
# (SecHeaders) Strict-Transport-Security: max-age=SECONDS ; includeSubDomains
# (SecHeaders) X-Frame-Options: deny | sameorigin | allow-from:DOMAIN
# (SecHeaders) X-Content-Type-Options: nosniff
# (SecHeaders) Content-Security-Policy: ver docs
# (SecHeaders) Referrer-Policy
# (SecHeaders) Permissions-Policy -> Working draft
# X-Permitted-Cross-Domain-Policies:
# Clear-Site-Data
# Cross-Origin-Embedder-Policy
# Cross-Origin-Opener-Policy
# Cross-Origin-Resource-Policy
# Cache-Control

## TODO
# Add output file (csv o algo asi)
# Add input list of URLs (from file or stdin)
# Identify headers with incorrect config values

parser = argparse.ArgumentParser(description='HTTP headers PoC')
parser.add_argument('--url', type=str, help='target URL', required=True)
parser.add_argument('--allow_redirects', action='store_true', help='allow redirects') 
args = parser.parse_args()

required_headers = ['Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Content-Security-Policy',
                    'Referrer-Policy',
                    'Permissions-Policy']

def main():
    init(autoreset=True)
    req = requests.get(args.url, allow_redirects=args.allow_redirects)
    
    print(Fore.YELLOW + f'[+] HTTP code: {req.status_code}')
    #print(colored(f'HTTP code: {req.status_code}', 'green', 'on_red'))
    #print(colored(f'HTTP code: {req.status_code}', 'blue', 'on_white', attrs=['underline']))
    
    print(Fore.YELLOW + f'[+] Headers found for {args.url}')
    for h in req.headers.items():
        print(h)

    found_headers = [x[0] for x in req.headers.items()]
    #print(found_headers)

    # Check for SecurityHeaders.com headers
    for h in required_headers:
        if h not in found_headers:
            print(Fore.RED + f'Missing {h}')
        else:
            print(Fore.GREEN + f'Found {h}')

    print('\n')

    # Analyse cookies
    print(Fore.YELLOW + f'[+] Checking cookies for {args.url}')
    for c in req.cookies:
        if c.secure:
            print(Fore.YELLOW + f'{c.name} -' + Fore.GREEN + f' Secure: {c.secure}')
        else:
            print(Fore.YELLOW + f'{c.name} -' + Fore.RED + f' Secure: {c.secure}')
        
        if c.has_nonstandard_attr("httponly"):
            print(Fore.YELLOW + f'{c.name} -' + Fore.GREEN + f' HttpOnly: {c.has_nonstandard_attr("httponly")}')
        else:
            print(Fore.YELLOW + f'{c.name} -' + Fore.RED + f' HttpOnly: {c.has_nonstandard_attr("httponly")}')


        
if __name__ == '__main__':
    main()
