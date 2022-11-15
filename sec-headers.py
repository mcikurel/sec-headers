import requests
import argparse
import json
from colorama import Fore, Back, Style, init

## OWASP Security Headers:
# (SecHeaders) Strict-Transport-Security: max-age=SECONDS ; includeSubDomains   (recommended: max-age=31536000 ; includeSubDomains)
# (SecHeaders) X-Frame-Options: deny | sameorigin | allow-from:DOMAIN           (recommended: deny)
# (SecHeaders) X-Content-Type-Options: nosniff                                  (recommended: nosniff)
# (SecHeaders) Content-Security-Policy: ver docs                                (recommended: check docs)
# (SecHeaders) Referrer-Policy                                                  (recommended: no-referrer)
# (SecHeaders) Permissions-Policy -> Working draft                              (recommended: check docs)
# X-Permitted-Cross-Domain-Policies                                             (recommended: none)
# Clear-Site-Data                                                               (recommended: "cache","cookies","storage")
# Cross-Origin-Embedder-Policy                                                  (recommended: require-corp)
# Cross-Origin-Opener-Policy                                                    (recommended: same-origin)
# Cross-Origin-Resource-Policy                                                  (recommended: same-origin)
# Cache-Control                                                                 (recommended: no-store, max-age=0)

## TODO
# Add output file (csv o algo asi)
# Add input list of URLs (from file or stdin)
# Identify headers with incorrect config values

parser = argparse.ArgumentParser(description='HTTP headers PoC')
parser.add_argument('--url', type=str, help='target URL', required=True)
parser.add_argument('--allow_redirects', action='store_true', help='allow redirects')
parser.add_argument('--verify_cert', action='store_true', help='verify SSL certificate')
args = parser.parse_args()

required_headers = ['Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Content-Security-Policy',
                    'Referrer-Policy',
                    'Permissions-Policy']

rec_values = {'strict-transport-security':'',
            'x-frame-options':'deny',
            'x-content-type-options':'sniff',
            'content-security-policy':'',
            'referrer-policy':'no-referrer',
            'permissions-policy':''}


def main():
    init(autoreset=True)
    req = requests.get(args.url, allow_redirects=args.allow_redirects, verify=args.verify_cert)
    
    print(Fore.YELLOW + f'[+] HTTP code: {req.status_code}')
    
    print(Fore.YELLOW + f'[+] Headers found for {args.url}')
    for h in req.headers.items():
        print(Fore.CYAN + f'{h[0]}:' + Fore.WHITE + f'{h[1]}')

    found_headers = [x[0].lower() for x in req.headers.items()]
    
    print()

    # Check for SecurityHeaders.com headers
    print(Fore.YELLOW + f'[+] Checking security headers for {args.url}')
    for h in required_headers:
        if h.lower() not in found_headers:
            print(Fore.RED + f'Missing {h}')
        else:
            print(Fore.GREEN + f'Found {h}')
            # if rec_values[h.lower()] != req.headers[h]: 
            #    print(Fore.YELLOW + f'Check values for {h}')
    
    print()

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

        if c.has_nonstandard_attr("samesite"):
            print(Fore.YELLOW + f'{c.name} -' + Fore.GREEN + f' SameSite: {c.has_nonstandard_attr("samesite")}')
        else:
            print(Fore.YELLOW + f'{c.name} -' + Fore.RED + f' SameSite: {c.has_nonstandard_attr("samesite")}')
    
    print()
    
    # Information disclosure headers
    print(Fore.YELLOW + f'[+] Checking for information disclosure via headers for {args.url}')

    get_owasp_list = requests.get('https://owasp.org/www-project-secure-headers/ci/headers_remove.json')
    owasp_remove_headers = json.loads(get_owasp_list.text)['headers']
        
    for h in owasp_remove_headers:
        if h.lower() in found_headers:
            print(Fore.RED + f'{h}: {req.headers[h]}')

   # Identify custom headers


if __name__ == '__main__':
    main()
