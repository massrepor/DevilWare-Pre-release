#!/usr/bin/env python3

import argparse
import sys
import os
import socket
import dns.resolver

import argparse
import phonenumbers
from phonenumbers import geocoder, carrier
import email_validator
import requests
import whois
import json
import sys
import os
from urllib.parse import quote
from colorama import init, Fore, Back, Style
import json
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    default_config = {
        "api_keys": {
            "numverify": "",
            "ipinfo": "",
            "shodan": "",
            "haveibeenpwned": ""
        },
        "settings": {
            "default_region": "US",
            "check_deliverability": False,
            "output_format": "text",
            "timeout": 10,
            "max_results": 50
        },
        "user": {
            "name": "Anonymous",
            "organization": "",
            "notes": "DevilWare OSINT Tool Configuration"
        },
        "advanced": {
            "enable_logging": False,
            "log_file": "devilware.log",
            "debug_mode": False,
            "custom_user_agent": "DevilWare-OSINT-Tool/1.0"
        }
    }
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            for key in default_config:
                if key in user_config:
                    default_config[key].update(user_config[key])
            return default_config
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not load config file: {str(e)}{Style.RESET_ALL}")
            return default_config
    else:
        try:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"{Fore.GREEN}Created default config file: {config_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}Warning: Could not create config file: {str(e)}{Style.RESET_ALL}")
        return default_config

def lookup_domain(domain):
    try:
        w = whois.whois(domain)
        result = f"Domain: {domain}\n"
        result += f"Registrar: {w.registrar or 'N/A'}\n"
        result += f"Creation Date: {w.creation_date or 'N/A'}\n"
        result += f"Expiration Date: {w.expiration_date or 'N/A'}\n"
        result += f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}\n"
        result += f"Registrant: {w.name or 'N/A'}\n"
        return result
    except Exception as e:
        return f"Error looking up domain: {str(e)}"

def lookup_phone(phone_number, region=None, api_key=None):
    try:
        parsed_number = phonenumbers.parse(phone_number, region)
        if not phonenumbers.is_valid_number(parsed_number):
            return "Invalid phone number."

        region_desc = geocoder.description_for_number(parsed_number, "en")
        carrier_name = carrier.name_for_number(parsed_number, "en")
        country_code = parsed_number.country_code
        national_number = parsed_number.national_number

        result = f"{Fore.CYAN}Phone Number: {Fore.YELLOW}{phone_number}{Style.RESET_ALL}\n"
        result += f"{Fore.GREEN}Valid: Yes{Style.RESET_ALL}\n"
        result += f"Country Code: {country_code}\n"
        result += f"National Number: {national_number}\n"
        result += f"Region: {region_desc}\n"
        result += f"Carrier: {carrier_name}\n"

        if api_key:
            try:
                numverify_url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}&country_code=&format=1"
                response = requests.get(numverify_url)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('valid'):
                        result += f"\nNumverify API Results:\n"
                        result += f"Valid: {data.get('valid')}\n"
                        result += f"Number: {data.get('number')}\n"
                        result += f"Local Format: {data.get('local_format')}\n"
                        result += f"International Format: {data.get('international_format')}\n"
                        result += f"Country Prefix: {data.get('country_prefix')}\n"
                        result += f"Country Code: {data.get('country_code')}\n"
                        result += f"Country Name: {data.get('country_name')}\n"
                        result += f"Location: {data.get('location')}\n"
                        result += f"Carrier: {data.get('carrier')}\n"
                        result += f"Line Type: {data.get('line_type')}\n"
                    else:
                        result += "\nNumverify: Invalid number\n"
            except Exception as e:
                result += f"\nNumverify API Error: {str(e)}\n"

        result += "Note: Reverse lookup requires additional services (e.g., Whitepages API).\n"

        return result
    except Exception as e:
        return f"Error parsing phone number: {str(e)}"

def lookup_email(email, check_deliverability=False):
    try:
        valid = email_validator.validate_email(email, check_deliverability=check_deliverability)
        result = f"Email: {email}\n"
        result += f"Valid Format: Yes\n"
        result += f"Local Part: {valid.local_part}\n"
        result += f"Domain: {valid.domain}\n"

        if check_deliverability:
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(valid.domain, 'MX')
                result += f"MX Records Found: Yes ({len(mx_records)} records)\n"
            except:
                result += "MX Records Found: No\n"
        else:
            result += "Deliverability check skipped.\n"

        result += "Note: Social media lookup requires additional services.\n"

        return result
    except email_validator.EmailNotValidError as e:
        return f"Invalid email: {str(e)}"
    except Exception as e:
        return f"Error checking email: {str(e)}"

def lookup_name(full_name):
    result = f"{Fore.CYAN}Name Investigation for: {Fore.YELLOW}{full_name}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Investigating name...{Style.RESET_ALL}")

    parts = full_name.strip().split()
    if len(parts) >= 2:
        first_name = parts[0]
        last_name = parts[-1]
        middle_names = ' '.join(parts[1:-1]) if len(parts) > 2 else ''
        
        result += f"{Fore.GREEN}Parsed Information:{Style.RESET_ALL}\n"
        result += f"  First Name: {first_name}\n"
        result += f"  Last Name: {last_name}\n"
        if middle_names:
            result += f"  Middle Name(s): {middle_names}\n"
        
        result += f"  Full Name: {full_name}\n"
        result += f"  Name Length: {len(full_name)} characters\n"
        
        initials = first_name[0].upper() + last_name[0].upper()
        result += f"  Initials: {initials}\n"
        
        result += f"\n{Fore.CYAN}Potential Variations:{Style.RESET_ALL}\n"
        variations = [
            f"{first_name} {last_name}",
            f"{first_name[0]}. {last_name}",
            f"{first_name} {last_name[0]}.",
            f"{last_name}, {first_name}",
        ]
        if middle_names:
            variations.extend([
                f"{first_name} {middle_names} {last_name}",
                f"{first_name[0]}. {middle_names} {last_name}",
            ])
        
        for variation in variations[:6]:  # Limit to 6 variations
            result += f"  • {variation}\n"
            
    else:
        result += f"{Fore.YELLOW}Could not parse first/last name from: {full_name}{Style.RESET_ALL}\n"
        result += f"  Please enter full name as 'First Last' or 'First Middle Last'\n"

    result += f"\n{Fore.CYAN}Online Search Suggestions:{Style.RESET_ALL}\n"
    search_queries = [
        f'"{full_name}" site:linkedin.com',
        f'"{full_name}" site:facebook.com',
        f'"{full_name}" email',
        f'"{full_name}" phone',
        f'"{full_name}" address',
    ]
    
    for query in search_queries:
        result += f"  • {query}\n"

    result += f"\n{Fore.YELLOW}People Search Resources:{Style.RESET_ALL}\n"
    resources = [
        ("Pipl", "https://pipl.com/"),
        ("Spokeo", "https://www.spokeo.com/"),
        ("BeenVerified", "https://www.beenverified.com/"),
        ("Intelius", "https://www.intelius.com/"),
        ("Whitepages", "https://www.whitepages.com/"),
    ]
    
    for name, url in resources:
        result += f"  • {name}: {url}\n"

    result += f"\n{Fore.CYAN}Note: Comprehensive name investigation typically requires:{Style.RESET_ALL}\n"
    result += f"  • Paid people search databases\n"
    result += f"  • Public records access\n"
    result += f"  • Social media investigation\n"
    result += f"  • Professional networking sites\n"
    result += f"  • This tool provides basic analysis and search guidance\n"

    return result

def lookup_ip(ip_address, api_key=None):
    try:
        url = f"https://ipinfo.io/{ip_address}/json"
        if api_key:
            url += f"?token={api_key}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            result = f"IP Address: {ip_address}\n"
            result += f"Hostname: {data.get('hostname', 'N/A')}\n"
            result += f"City: {data.get('city', 'N/A')}\n"
            result += f"Region: {data.get('region', 'N/A')}\n"
            result += f"Country: {data.get('country', 'N/A')}\n"
            result += f"Location: {data.get('loc', 'N/A')}\n"
            result += f"Organization: {data.get('org', 'N/A')}\n"
            if 'postal' in data:
                result += f"Postal Code: {data['postal']}\n"
            if 'timezone' in data:
                result += f"Timezone: {data['timezone']}\n"
            return result
        else:
            return f"Error: Unable to fetch IP info (Status: {response.status_code})"
    except Exception as e:
        return f"Error looking up IP: {str(e)}"

def lookup_social_media(query):
    result = f"{Fore.CYAN}Social Media Search for: {Fore.YELLOW}{query}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Searching social media platforms...{Style.RESET_ALL}")

    platforms = {
        'Twitter/X': f'https://twitter.com/{query}',
        'Instagram': f'https://www.instagram.com/{query}/',
        'Facebook': f'https://www.facebook.com/{query}',
        'LinkedIn': f'https://www.linkedin.com/in/{query}',
        'TikTok': f'https://www.tiktok.com/@{query}',
        'YouTube': f'https://www.youtube.com/@{query}',
        'Reddit': f'https://www.reddit.com/user/{query}',
        'GitHub': f'https://github.com/{query}',
        'Medium': f'https://medium.com/@{query}',
        'Pinterest': f'https://www.pinterest.com/{query}/'
    }

    found_profiles = []
    for platform, url in platforms.items():
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.head(url, headers=headers, timeout=5, allow_redirects=True)

            if response.status_code == 200:
                found_profiles.append((platform, url))
                result += f"{Fore.GREEN}✓ {Fore.WHITE}{platform}: {Fore.GREEN}Profile Found{Style.RESET_ALL}\n"
            elif response.status_code in [301, 302, 303, 307, 308]:
                found_profiles.append((platform, url))
                result += f"{Fore.GREEN}✓ {Fore.WHITE}{platform}: {Fore.GREEN}Profile Found (Redirect){Style.RESET_ALL}\n"
            else:
                result += f"{Fore.RED}✗ {Fore.WHITE}{platform}: {Fore.RED}Not Found{Style.RESET_ALL}\n"

        except requests.exceptions.RequestException:
            result += f"{Fore.YELLOW}? {Fore.WHITE}{platform}: {Fore.YELLOW}Error checking{Style.RESET_ALL}\n"

    result += f"\n{Fore.CYAN}Summary: {len(found_profiles)} profiles found across {len(platforms)} platforms{Style.RESET_ALL}\n"

    if found_profiles:
        result += f"\n{Fore.YELLOW}Found Profiles:{Style.RESET_ALL}\n"
        for platform, url in found_profiles:
            result += f"• {platform}: {url}\n"

    result += f"\n{Fore.YELLOW}Note: This tool checks for public profile existence only.{Style.RESET_ALL}\n"
    result += f"{Fore.YELLOW}For comprehensive social media intelligence, consider using specialized tools.{Style.RESET_ALL}\n"

    return result

def lookup_username(username):
    platforms = {
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}/',
        'Facebook': f'https://www.facebook.com/{username}',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'GitHub': f'https://github.com/{username}',
        'YouTube': f'https://www.youtube.com/@{username}',
        'TikTok': f'https://www.tiktok.com/@{username}',
        'LinkedIn': f'https://www.linkedin.com/in/{username}',
        'Pinterest': f'https://www.pinterest.com/{username}/',
        'Tumblr': f'https://{username}.tumblr.com',
        'Medium': f'https://medium.com/@{username}',
        'Dev.to': f'https://dev.to/{username}',
        'HackerNews': f'https://news.ycombinator.com/user?id={username}',
    }
    
    result = f"{Fore.CYAN}Username Lookup: {Fore.YELLOW}{username}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Checking username across platforms...{Style.RESET_ALL}")
    
    for i, (platform, url) in enumerate(platforms.items()):
        try:
            response = requests.head(url, timeout=5)
            if response.status_code == 200:
                result += f"{Fore.GREEN}✓ {Fore.WHITE}{platform}: {Fore.GREEN}Available/Profile Found{Style.RESET_ALL} - {url}\n"
            else:
                result += f"{Fore.RED}✗ {Fore.WHITE}{platform}: {Fore.RED}Not Found{Style.RESET_ALL}\n"
        except:
            result += f"{Fore.YELLOW}? {Fore.WHITE}{platform}: {Fore.YELLOW}Error checking{Style.RESET_ALL}\n"
        
        progress = (i + 1) / len(platforms) * 100
        print(f"\r{Fore.BLUE}Progress: {progress:.1f}% complete{Style.RESET_ALL}", end="", flush=True)
    
    print(f"\r{Fore.GREEN}Username check completed!{Style.RESET_ALL}")
    return result
    
    return result

def lookup_breach(email):
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
        headers = {'User-Agent': 'DevilWare-OSINT-Tool'}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            breaches = response.json()
            result = f"{Fore.CYAN}Breach Check for: {Fore.YELLOW}{email}{Style.RESET_ALL}\n"
            result += f"{Fore.RED}Found in {len(breaches)} breach(es):{Style.RESET_ALL}\n\n"
            for breach in breaches:
                result += f"{Fore.MAGENTA}• {Fore.WHITE}{breach['Name']}: {Fore.RED}{breach['Description'][:100]}...{Style.RESET_ALL}\n"
                result += f"  {Fore.CYAN}Breach Date: {Fore.WHITE}{breach['BreachDate']}{Style.RESET_ALL}\n"
                result += f"  {Fore.CYAN}Data Classes: {Fore.WHITE}{', '.join(breach['DataClasses'][:5])}{Style.RESET_ALL}\n\n"
        elif response.status_code == 404:
            result = f"{Fore.CYAN}Breach Check for: {Fore.YELLOW}{email}{Style.RESET_ALL}\n{Fore.GREEN}No breaches found for this email.{Style.RESET_ALL}\n"
        else:
            result = f"Error checking breaches: HTTP {response.status_code}\n"
    except Exception as e:
        result = f"Error checking breaches: {str(e)}\n"
    
    return result

def lookup_pastebin(query):
    try:
        url = f"https://psbdmp.ws/api/search/{quote(query)}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result = f"Pastebin Search for: {query}\n"
            if data.get('count', 0) > 0:
                result += f"Found {data['count']} paste(s):\n\n"
                for paste in data.get('data', [])[:5]:
                    result += f"• ID: {paste['id']}\n"
                    result += f"  Tags: {', '.join(paste.get('tags', []))}\n"
                    result += f"  URL: https://psbdmp.ws/{paste['id']}\n\n"
            else:
                result += "No pastes found.\n"
        else:
            result = f"Pastebin search error: HTTP {response.status_code}\n"
    except Exception as e:
        result = f"Error searching Pastebin: {str(e)}\n"
    
    return result

def lookup_shodan(ip, api_key=None):
    if not api_key:
        return "Shodan lookup requires API key. Get one at https://account.shodan.io/\n"
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            result = f"Shodan Lookup for: {ip}\n"
            result += f"Organization: {data.get('org', 'N/A')}\n"
            result += f"ISP: {data.get('isp', 'N/A')}\n"
            result += f"Country: {data.get('country_name', 'N/A')}\n"
            result += f"City: {data.get('city', 'N/A')}\n"
            result += f"Ports: {', '.join(map(str, data.get('ports', [])))}\n"
            
            if 'vulns' in data:
                result += f"Vulnerabilities: {len(data['vulns'])}\n"
            
            if data.get('data'):
                result += f"\nServices:\n"
                for service in data['data'][:3]:
                    result += f"• Port {service['port']}: {service.get('product', 'Unknown')}\n"
        else:
            result = f"Shodan error: {response.json().get('error', 'Unknown error')}\n"
    except Exception as e:
        result = f"Error with Shodan: {str(e)}\n"
    
    return result

def lookup_reverse_image(image_url):
    result = f"{Fore.CYAN}Reverse Image Search for: {Fore.YELLOW}{image_url}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Performing reverse image search...{Style.RESET_ALL}")

    search_engines = {
        'Google': f'https://www.google.com/searchbyimage?image_url={quote(image_url)}',
        'TinEye': f'https://tineye.com/search?url={quote(image_url)}',
        'Yandex': f'https://yandex.com/images/search?rpt=imageview&url={quote(image_url)}',
        'Bing': f'https://www.bing.com/images/search?q=imgurl:{quote(image_url)}&view=detailv2&iss=sbi',
        'Baidu': f'https://image.baidu.com/pcdutu?queryImageUrl={quote(image_url)}'
    }

    result += f"{Fore.GREEN}Reverse Image Search URLs:{Style.RESET_ALL}\n"
    for engine, url in search_engines.items():
        result += f"• {engine}: {url}\n"

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        result += f"\n{Fore.CYAN}Additional Analysis:{Style.RESET_ALL}\n"

        if image_url.startswith(('http://', 'https://')):
            try:
                response = requests.head(image_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')
                    if 'image' in content_type.lower():
                        result += f"{Fore.GREEN}✓ Image URL is accessible{Style.RESET_ALL}\n"
                        result += f"  Content-Type: {content_type}\n"
                    else:
                        result += f"{Fore.YELLOW}⚠ URL exists but may not be an image{Style.RESET_ALL}\n"
                        result += f"  Content-Type: {content_type}\n"
                else:
                    result += f"{Fore.RED}✗ Image URL not accessible (Status: {response.status_code}){Style.RESET_ALL}\n"
            except:
                result += f"{Fore.YELLOW}? Could not verify image URL accessibility{Style.RESET_ALL}\n"

        domain = image_url.split('/')[2] if '//' in image_url else 'unknown'
        result += f"  Hosting Domain: {domain}\n"

        if any(ext in image_url.lower() for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']):
            result += f"{Fore.GREEN}✓ URL appears to be a direct image link{Style.RESET_ALL}\n"
        else:
            result += f"{Fore.YELLOW}⚠ URL may not be a direct image link{Style.RESET_ALL}\n"

    except Exception as e:
        result += f"{Fore.RED}Error during analysis: {str(e)}{Style.RESET_ALL}\n"

    result += f"\n{Fore.YELLOW}Instructions:{Style.RESET_ALL}\n"
    result += f"1. Open the search URLs above in your browser\n"
    result += f"2. Each engine will show similar images and sources\n"
    result += f"3. Look for the original source, duplicates, or related content\n"
    result += f"4. Check metadata for additional information\n\n"

    result += f"{Fore.CYAN}Note: For advanced reverse image search, consider using:{Style.RESET_ALL}\n"
    result += f"• Google Images, TinEye, or PimEyes (paid)\n"
    result += f"• Image metadata analysis tools\n"
    result += f"• Forensic image analysis software\n"

    return result

def lookup_darkweb(query):
    result = f"Dark Web Search for: {query}\n\n"
    result += "WARNING: Dark web access requires Tor and is highly dangerous.\n"
    result += "This tool does not provide actual dark web access.\n\n"
    result += "Recommended tools for dark web OSINT:\n"
    result += "• Tor Browser\n"
    result += "• Ahmia (dark web search engine)\n"
    result += "• Onion links from trusted sources\n\n"
    result += "Legal Note: Ensure all activities comply with local laws.\n"
    return result
def lookup_dns(domain):
    result = f"DNS Lookup for: {domain}\n\n"
    try:
        import dns.resolver
        
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result += "A Records:\n"
            for rdata in a_records:
                result += f"  {rdata.address}\n"
        except:
            result += "A Records: None found\n"
        
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result += "\nMX Records:\n"
            for rdata in mx_records:
                result += f"  {rdata.preference} {rdata.exchange}\n"
        except:
            result += "MX Records: None found\n"
        
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            result += "\nNS Records:\n"
            for rdata in ns_records:
                result += f"  {rdata.target}\n"
        except:
            result += "NS Records: None found\n"
        
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            result += "\nTXT Records:\n"
            for rdata in txt_records:
                result += f"  {rdata.strings}\n"
        except:
            result += "TXT Records: None found\n"
            
    except Exception as e:
        result += f"Error performing DNS lookup: {str(e)}\n"
    
    return result

def lookup_subdomains(domain):
    result = f"{Fore.CYAN}Subdomain Enumeration for: {Fore.YELLOW}{domain}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Enumerating subdomains...{Style.RESET_ALL}")

    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

    result += f"{Fore.GREEN}Target Domain: {domain}{Style.RESET_ALL}\n\n"

    # Common subdomain prefixes
    common_prefixes = [
        'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'dev', 'staging', 'test',
        'secure', 'portal', 'login', 'auth', 'webmail', 'remote', 'vpn', 'cloud',
        'support', 'help', 'docs', 'wiki', 'forum', 'community', 'shop', 'store',
        'mobile', 'm', 'beta', 'demo', 'sandbox', 'internal', 'intranet', 'corp',
        'corporate', 'partner', 'partners', 'client', 'clients', 'customer', 'customers'
    ]

    found_subdomains = []
    total_checked = 0

    result += f"{Fore.CYAN}Checking common subdomains...{Style.RESET_ALL}\n"

    for prefix in common_prefixes:
        total_checked += 1
        subdomain = f"{prefix}.{domain}"
        
        try:
            # Try to resolve the subdomain
            ip = socket.gethostbyname(subdomain)
            found_subdomains.append((subdomain, ip))
            result += f"{Fore.GREEN}✓ Found: {subdomain} -> {ip}{Style.RESET_ALL}\n"
        except socket.gaierror:
            # Subdomain doesn't resolve, skip
            pass

    result += f"\n{Fore.CYAN}Enumeration Results:{Style.RESET_ALL}\n"
    result += f"  Total checked: {total_checked}\n"
    result += f"  Found: {len(found_subdomains)}\n"

    if found_subdomains:
        result += f"\n{Fore.GREEN}Discovered Subdomains:{Style.RESET_ALL}\n"
        for subdomain, ip in found_subdomains:
            result += f"  • {subdomain} ({ip})\n"
    else:
        result += f"{Fore.YELLOW}No common subdomains found.{Style.RESET_ALL}\n"

    # DNS record types to check
    result += f"\n{Fore.CYAN}DNS Records for {domain}:{Style.RESET_ALL}\n"
    
    try:
        # A records
        a_records = socket.getaddrinfo(domain, None)
        if a_records:
            result += f"{Fore.GREEN}A Records:{Style.RESET_ALL}\n"
            ips = set()
            for record in a_records:
                ip = record[4][0]
                if ip not in ips:
                    ips.add(ip)
                    result += f"  • {ip}\n"
        
        # MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if mx_records:
                result += f"{Fore.GREEN}MX Records (Mail Servers):{Style.RESET_ALL}\n"
                for mx in mx_records:
                    result += f"  • {mx.exchange} (priority: {mx.preference})\n"
        except:
            result += f"{Fore.YELLOW}No MX records found{Style.RESET_ALL}\n"
            
        # NS records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            if ns_records:
                result += f"{Fore.GREEN}NS Records (Name Servers):{Style.RESET_ALL}\n"
                for ns in ns_records:
                    result += f"  • {ns.to_text()}\n"
        except:
            result += f"{Fore.YELLOW}No NS records found{Style.RESET_ALL}\n"
            
    except Exception as e:
        result += f"{Fore.RED}Error checking DNS records: {str(e)}{Style.RESET_ALL}\n"

    result += f"\n{Fore.CYAN}Advanced Enumeration Tools:{Style.RESET_ALL}\n"
    result += f"  • Sublist3r: https://github.com/aboul3la/Sublist3r\n"
    result += f"  • Amass: https://github.com/OWASP/Amass\n"
    result += f"  • Subfinder: https://github.com/projectdiscovery/subfinder\n"
    result += f"  • Certificate Transparency logs\n"
    result += f"  • DNS brute force tools\n"

    result += f"\n{Fore.YELLOW}Note: This is a basic enumeration. For comprehensive results:{Style.RESET_ALL}\n"
    result += f"  • Use dedicated subdomain enumeration tools\n"
    result += f"  • Check certificate transparency logs\n"
    result += f"  • Use DNS zone transfers (if allowed)\n"
    result += f"  • Monitor for new subdomains over time\n"

    return result

def lookup_ports(ip):
    result = f"{Fore.CYAN}Port Scan for: {Fore.YELLOW}{ip}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Scanning ports...{Style.RESET_ALL}")

    # Validate IP address
    try:
        socket.inet_aton(ip)
    except socket.error:
        return f"{Fore.RED}Invalid IP address: {ip}{Style.RESET_ALL}\n"

    # Comprehensive port list with categories
    port_categories = {
        'Web Services': [80, 443, 8080, 8443, 3000, 5000, 8000, 8888],
        'Mail Services': [25, 110, 143, 465, 587, 993, 995],
        'File Transfer': [21, 22, 23, 69, 115, 139, 445],
        'Database': [1433, 1521, 3306, 5432, 27017, 6379],
        'Remote Access': [22, 23, 3389, 5900, 5901],
        'DNS & Network': [53, 67, 68, 123, 161, 162],
        'Other Common': [135, 137, 138, 389, 636, 989, 990]
    }

    open_ports = []
    total_scanned = 0

    for category, ports in port_categories.items():
        result += f"{Fore.GREEN}{category}:{Style.RESET_ALL}\n"
        for port in ports:
            total_scanned += 1
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # Increased timeout for better reliability
                result_conn = sock.connect_ex((ip, port))
                if result_conn == 0:
                    open_ports.append((port, category))
                    result += f"  {Fore.GREEN}✓ Port {port} - OPEN{Style.RESET_ALL}\n"
                else:
                    result += f"  {Fore.RED}✗ Port {port} - CLOSED{Style.RESET_ALL}\n"
                sock.close()
            except Exception as e:
                result += f"  {Fore.YELLOW}? Port {port} - ERROR ({str(e)}){Style.RESET_ALL}\n"

        result += "\n"

    result += f"{Fore.CYAN}Scan Summary:{Style.RESET_ALL}\n"
    result += f"  Total ports scanned: {total_scanned}\n"
    result += f"  Open ports found: {len(open_ports)}\n"

    if open_ports:
        result += f"\n{Fore.GREEN}Open Ports Details:{Style.RESET_ALL}\n"
        for port, category in open_ports:
            service_name = get_service_name(port)
            result += f"  • Port {port} ({service_name}) - {category}\n"

    result += f"\n{Fore.CYAN}Security Recommendations:{Style.RESET_ALL}\n"
    if len(open_ports) > 5:
        result += f"  {Fore.YELLOW}⚠ Many open ports detected - review firewall rules{Style.RESET_ALL}\n"
    if any(port in [22, 23, 3389] for port, _ in open_ports):
        result += f"  {Fore.YELLOW}⚠ Remote access ports open - ensure proper authentication{Style.RESET_ALL}\n"
    if any(port in [80, 443] for port, _ in open_ports):
        result += f"  {Fore.GREEN}✓ Web services detected - check for web applications{Style.RESET_ALL}\n"

    result += f"\n{Fore.CYAN}Advanced Scanning Tools:{Style.RESET_ALL}\n"
    result += f"  • Nmap: https://nmap.org/\n"
    result += f"  • Masscan: https://github.com/robertdavidgraham/masscan\n"
    result += f"  • ZMap: https://zmap.io/\n"

    result += f"\n{Fore.YELLOW}Note: This is a basic TCP connect scan. For comprehensive security assessment:{Style.RESET_ALL}\n"
    result += f"  • Use Nmap with service/version detection (-sV)\n"
    result += f"  • Perform UDP scanning (-sU)\n"
    result += f"  • Use vulnerability scanners\n"
    result += f"  • Consider firewall evasion techniques\n"

    return result

def get_service_name(port):
    """Get common service name for a port"""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
        135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'SMB',
        143: 'IMAP', 161: 'SNMP', 162: 'SNMP', 389: 'LDAP',
        443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP',
        636: 'LDAPS', 989: 'FTPS', 990: 'FTPS', 993: 'IMAPS',
        995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5000: 'UPnP', 5432: 'PostgreSQL', 5900: 'VNC',
        6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    return services.get(port, 'Unknown')

def lookup_mac(mac_address):
    result = f"MAC Address Lookup: {mac_address}\n\n"
    mac = ''.join(c for c in mac_address.upper() if c.isalnum())[:6]
    
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            vendor = response.text
            result += f"Vendor: {vendor}\n"
        else:
            result += "Vendor: Not found in database\n"
            
    except Exception as e:
        result += f"Error looking up MAC: {str(e)}\n"
    
    oui_db = {
        '00:50:56': 'VMware',
        '08:00:27': 'Oracle VirtualBox',
        '00:0C:29': 'VMware',
        '00:05:69': 'VMware',
        '00:1C:14': 'VMware',
        '00:1C:42': 'Parallels',
        '02:42:AC': 'Docker',
        'B8:27:EB': 'Raspberry Pi Foundation',
        'DC:A6:32': 'Raspberry Pi Foundation',
        'E4:5F:01': 'Raspberry Pi Foundation'
    }
    
    mac_prefix = mac_address.upper()[:8]
    if mac_prefix in oui_db:
        result += f"Common Association: {oui_db[mac_prefix]}\n"
    
    return result

def lookup_vin(vin):
    result = f"{Fore.CYAN}VIN Lookup for: {Fore.YELLOW}{vin}{Style.RESET_ALL}\n\n"
    print(f"{Fore.CYAN}Analyzing VIN...{Style.RESET_ALL}")

    if len(vin) != 17:
        result += f"{Fore.RED}Error: VIN must be exactly 17 characters long. Provided: {len(vin)}{Style.RESET_ALL}\n"
        return result

    vin = vin.upper()

    # VIN validation and checksum calculation
    weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]
    transliterate = {
        'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
        'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
        'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9
    }

    try:
        total = 0
        for i, char in enumerate(vin):
            if char.isdigit():
                value = int(char)
            elif char in transliterate:
                value = transliterate[char]
            else:
                result += f"{Fore.RED}Error: Invalid character '{char}' at position {i+1}{Style.RESET_ALL}\n"
                return result
            total += value * weights[i]

        check_digit = total % 11
        if check_digit == 10:
            check_digit = 'X'

        calculated_check = str(check_digit)
        actual_check = vin[8]

        if calculated_check == actual_check:
            result += f"{Fore.GREEN}✓ Checksum Validation: VALID{Style.RESET_ALL}\n"
        else:
            result += f"{Fore.RED}✗ Checksum Validation: INVALID{Style.RESET_ALL}\n"
            result += f"  Calculated: {calculated_check}, Actual: {actual_check}\n"

        # VIN breakdown
        result += f"\n{Fore.CYAN}VIN Breakdown:{Style.RESET_ALL}\n"
        result += f"  World Manufacturer Identifier (WMI): {Fore.YELLOW}{vin[:3]}{Style.RESET_ALL}\n"
        result += f"  Vehicle Descriptor Section (VDS): {Fore.YELLOW}{vin[3:8]}{Style.RESET_ALL}\n"
        result += f"  Check Digit: {Fore.YELLOW}{vin[8]}{Style.RESET_ALL}\n"
        result += f"  Model Year: {Fore.YELLOW}{vin[9]}{Style.RESET_ALL}\n"
        result += f"  Plant Code: {Fore.YELLOW}{vin[10]}{Style.RESET_ALL}\n"
        result += f"  Sequential Number: {Fore.YELLOW}{vin[11:]}{Style.RESET_ALL}\n"

        # Manufacturer lookup
        wmi_manufacturers = {
            '1G1': 'Chevrolet', '1G6': 'Cadillac', '1GM': 'Pontiac', '1G': 'General Motors',
            'JH4': 'Acura', 'JF1': 'Subaru', 'JM1': 'Mazda', 'JN8': 'Nissan',
            'JS': 'Suzuki', 'JT': 'Toyota', 'KL': 'Daewoo', 'KM8': 'Hyundai',
            'KNA': 'Kia', 'SAL': 'Land Rover', 'SAJ': 'Jaguar', 'TRU': 'Audi',
            'VF1': 'Renault', 'VF3': 'Peugeot', 'VF6': 'Citroën', 'VF7': 'Citroën',
            'VF8': 'Matra', 'VSS': 'SEAT', 'WAU': 'Audi', 'WBA': 'BMW',
            'WDB': 'Mercedes-Benz', 'WDD': 'Mercedes-Benz', 'WMW': 'Mini',
            'WVW': 'Volkswagen', 'YV1': 'Volvo', 'ZAM': 'Maserati',
            'ZAR': 'Alfa Romeo', 'ZHW': 'Lamborghini', '1FA': 'Ford',
            '1FT': 'Ford', '1FM': 'Ford', '1FD': 'Ford', '2HG': 'Honda',
            '3VW': 'Volkswagen', '4S': 'Subaru', '4T': 'Toyota', '5FN': 'Honda',
            '5N1': 'Nissan', '5T': 'Toyota', 'JA': 'Isuzu', 'JHM': 'Honda',
            'JNK': 'Infiniti', 'JTE': 'Toyota', 'JTH': 'Lexus'
        }

        wmi = vin[:3]
        manufacturer = wmi_manufacturers.get(wmi, 'Unknown')
        result += f"\n{Fore.GREEN}Manufacturer: {manufacturer}{Style.RESET_ALL}\n"

        # Model year lookup
        model_years = {
            'A': 2010, 'B': 2011, 'C': 2012, 'D': 2013, 'E': 2014, 'F': 2015,
            'G': 2016, 'H': 2017, 'J': 2018, 'K': 2019, 'L': 2020, 'M': 2021,
            'N': 2022, 'P': 2023, 'R': 2024, 'S': 2025, 'T': 2026, 'V': 2027,
            'W': 2028, 'X': 2029, 'Y': 2030, '1': 2001, '2': 2002, '3': 2003,
            '4': 2004, '5': 2005, '6': 2006, '7': 2007, '8': 2008, '9': 2009
        }

        model_year = model_years.get(vin[9], 'Unknown')
        result += f"  Model Year: {model_year}\n"

        # Country of origin
        country_codes = {
            '1': 'United States', '2': 'Canada', '3': 'Mexico', '4': 'United States',
            '5': 'United States', 'J': 'Japan', 'K': 'South Korea', 'L': 'China',
            'S': 'United Kingdom', 'V': 'France', 'W': 'Germany', 'Y': 'Sweden',
            'Z': 'Italy'
        }

        country = country_codes.get(vin[0], 'Unknown')
        result += f"  Country of Origin: {country}\n"

        result += f"\n{Fore.CYAN}Vehicle History Resources:{Style.RESET_ALL}\n"
        result += f"  • Carfax: https://www.carfax.com/\n"
        result += f"  • AutoCheck: https://www.autocheck.com/\n"
        result += f"  • CARFAX Canada: https://www.carfax.ca/\n"
        result += f"  • NICB VINCheck: https://www.nicb.org/vincheck\n"

        result += f"\n{Fore.CYAN}Additional Research:{Style.RESET_ALL}\n"
        result += f"  • Search: \"{vin}\" vehicle history\n"
        result += f"  • Search: \"{manufacturer} {vin[3:8]}\" model info\n"
        result += f"  • Check local DMV databases\n"
        result += f"  • Contact manufacturer for recall information\n"

        result += f"\n{Fore.YELLOW}Note: This provides basic VIN analysis. For complete vehicle history including:{Style.RESET_ALL}\n"
        result += f"  • Accident reports, title information, odometer readings\n"
        result += f"  • Service records, warranty status, theft records\n"
        result += f"  • Use professional vehicle history services\n"

    except Exception as e:
        result += f"{Fore.RED}Error processing VIN: {str(e)}{Style.RESET_ALL}\n"

    return result
def interactive_menu():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║{Fore.YELLOW}                    DevilWare OSINT Tool                     {Fore.RED}║
║{Fore.YELLOW}                     Pre Release Version                     {Fore.RED}║
║{Fore.MAGENTA}                       By. 666Reaper                             {Fore.RED}║
║{Fore.GREEN}                                                   {Fore.RED}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.CYAN}Available OSINT Operations:{Style.RESET_ALL}
{Fore.GREEN}1.{Fore.WHITE}  📞 Phone Number Lookup
{Fore.GREEN}2.{Fore.WHITE}  📧 Email Analysis
{Fore.GREEN}3.{Fore.WHITE}  👤 Name Investigation
{Fore.GREEN}4.{Fore.WHITE}  🌐 IP Address Geolocation
{Fore.GREEN}5.{Fore.WHITE}  🏠 Domain WHOIS
{Fore.GREEN}6.{Fore.WHITE}  👥 Social Media Search
{Fore.GREEN}7.{Fore.WHITE}  🔍 Username Availability Check
{Fore.GREEN}8.{Fore.WHITE}  🚨 Email Breach Check
{Fore.GREEN}9.{Fore.WHITE}  📄 Pastebin Search
{Fore.GREEN}10.{Fore.WHITE} 🔒 Shodan IP Scan
{Fore.GREEN}11.{Fore.WHITE} 🖼️  Reverse Image Search
{Fore.GREEN}12.{Fore.WHITE} 🌑 Dark Web Info (Educational)
{Fore.GREEN}13.{Fore.WHITE} 🌐 DNS Lookup
{Fore.GREEN}14.{Fore.WHITE} 🔎 Subdomain Enumeration
{Fore.GREEN}15.{Fore.WHITE} 🚪 Port Scanning
{Fore.GREEN}16.{Fore.WHITE} 💻 MAC Address Lookup
{Fore.GREEN}17.{Fore.WHITE} 🚗 VIN Decoder

{Fore.RED}0.{Fore.WHITE} 👋 Exit{Style.RESET_ALL}
""")
    
    while True:
        try:
            choice = input("Select operation (0-17): ").strip()
            
            if choice == "0":
                print("Goodbye!")
                break
            
            operations = {
                "1": ("phone", "Enter phone number (with country code): "),
                "2": ("email", "Enter email address: "),
                "3": ("name", "Enter full name: "),
                "4": ("ip", "Enter IP address: "),
                "5": ("domain", "Enter domain name: "),
                "6": ("social", "Enter search term: "),
                "7": ("username", "Enter username: "),
                "8": ("breach", "Enter email for breach check: "),
                "9": ("pastebin", "Enter search term: "),
                "10": ("shodan", "Enter IP address: "),
                "11": ("reverseimage", "Enter image URL: "),
                "12": ("darkweb", "Enter search term: "),
                "13": ("dns", "Enter domain name: "),
                "14": ("subdomains", "Enter domain name: "),
                "15": ("ports", "Enter IP address: "),
                "16": ("mac", "Enter MAC address: "),
                "17": ("vin", "Enter VIN (17 characters): "),
            }
            
            if choice in operations:
                lookup_type, prompt = operations[choice]
                query = input(prompt).strip()
                if query:

                    class MockArgs:
                        def __init__(self, config):
                            self.api_key = None
                            self.region = config["settings"]["default_region"]
                            self.check_deliverability = config["settings"]["check_deliverability"]
                            self.output_format = config["settings"]["output_format"]
                    
                    args = MockArgs(config)
                    result = perform_lookup(lookup_type, query, args, config)
                    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}DevilWare OSINT Results:{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
                    print(result)
                    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
                else:
                    print("No input provided.\n")
            else:
                print("Invalid choice. Please select 0-17.\n")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {str(e)}\n")

def main():
    init(autoreset=True)
    config = load_config()
    
    print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}🔥 Welcome to DevilWare OSINT Tool - Pre Release Version 🔥{Style.RESET_ALL}")
    print(f"{Fore.CYAN}⚡ One of the Most Powerful OSINT Tools Available ⚡{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}👤 Created by 666Reaper 👤{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*70}{Style.RESET_ALL}")
    print()
    if len(sys.argv) == 1:
        interactive_menu()
        return
    
    parser = argparse.ArgumentParser(description="DevilWare OSINT Tool - Pre Release Version")
    parser.add_argument("type", choices=["phone", "email", "name", "ip", "domain", "social", "username", "breach", "pastebin", "shodan", "reverseimage", "darkweb", "dns", "subdomains", "ports", "mac", "vin"],
                        help="Type of lookup")
    parser.add_argument("query", nargs='?', help="The item to lookup (optional if using --batch-file)")
    parser.add_argument("--api-key", help="API key for services that require it (e.g., ipinfo.io, shodan)")
    parser.add_argument("--region", default=config["settings"]["default_region"], help="Default region for phone number parsing (e.g., US, GB)")
    parser.add_argument("--check-deliverability", action="store_true", default=config["settings"]["check_deliverability"], help="Check email deliverability")
    parser.add_argument("--output-format", choices=["text", "json"], default=config["settings"]["output_format"], help="Output format")
    parser.add_argument("--batch-file", help="File containing multiple queries (one per line)")

    args = parser.parse_args()

    if args.batch_file:
        try:
            with open(args.batch_file, 'r') as f:
                queries = [line.strip() for line in f if line.strip()]
            results = []
            for query in queries:
                result = perform_lookup(args.type, query, args, config)
                results.append({"query": query, "result": result})
            if args.output_format == "json":
                import json
                print(json.dumps(results, indent=2))
            else:
                for item in results:
                    print(f"Query: {item['query']}")
                    print(item['result'])
                    print("-" * 50)
        except FileNotFoundError:
            print(f"Error: Batch file '{args.batch_file}' not found.")
        return

    if not args.query:
        parser.error("query is required unless --batch-file is specified")

    result = perform_lookup(args.type, args.query, args, config)
    
    if args.output_format == "json":
        import json
        print(json.dumps({"query": args.query, "result": result}))
    else:
        print(result)

def perform_lookup(lookup_type, query, args, config=None):
    if config is None:
        config = load_config()
    
    api_key = args.api_key
    if not api_key:
        if lookup_type == "phone":
            api_key = config["api_keys"]["numverify"]
        elif lookup_type == "ip":
            api_key = config["api_keys"]["ipinfo"]
        elif lookup_type == "shodan":
            api_key = config["api_keys"]["shodan"]
        elif lookup_type == "breach":
            api_key = config["api_keys"]["haveibeenpwned"]
    
    if lookup_type == "phone":
        return lookup_phone(query, args.region, api_key)
    elif lookup_type == "email":
        return lookup_email(query, args.check_deliverability)
    elif lookup_type == "name":
        return lookup_name(query)
    elif lookup_type == "ip":
        return lookup_ip(query, api_key)
    elif lookup_type == "domain":
        return lookup_domain(query)
    elif lookup_type == "social":
        return lookup_social_media(query)
    elif lookup_type == "username":
        return lookup_username(query)
    elif lookup_type == "breach":
        return lookup_breach(query)
    elif lookup_type == "pastebin":
        return lookup_pastebin(query)
    elif lookup_type == "shodan":
        return lookup_shodan(query, api_key)
    elif lookup_type == "reverseimage":
        return lookup_reverse_image(query)
    elif lookup_type == "darkweb":
        return lookup_darkweb(query)
    elif lookup_type == "dns":
        return lookup_dns(query)
    elif lookup_type == "subdomains":
        return lookup_subdomains(query)
    elif lookup_type == "ports":
        return lookup_ports(query)
    elif lookup_type == "mac":
        return lookup_mac(query)
    elif lookup_type == "vin":
        return lookup_vin(query)

if __name__ == "__main__":
    main()