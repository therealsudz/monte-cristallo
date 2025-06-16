import requests
import json
import re
import phonenumbers
from phonenumbers import geocoder, carrier
import socket
import os
import sys
import time
import threading
from queue import Queue
import whois
import dns.resolver
import hashlib
import base64
import ipaddress
from urllib.parse import urlparse, urlunparse, urljoin
import random
import string
import speedtest
import qrcode
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
import lxml
import pythonping
import shutil

m_color = "\033[38;2;255;204;255m"
red = "\033[38;2;255;000;000m"
white = "\033[38;2;255;255;255m"
green = "\033[38;2;140;255;140m"
blue = "\033[38;2;000;000;255m"
yellow = "\033[38;2;255;255;000m"
cyan = "\033[38;2;0;255;255m"
reset_color = "\033[0m"

DEFAULT_PORT_SCAN_TIMEOUT = 0.5
DEFAULT_PORT_SCAN_THREADS = 50
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2", "admin",
    "panel", "cpanel", "vpn", "test", "dev", "staging", "api", "shop", "blog", "remote",
    "owa", "portal", "support", "secure", "internal", "mail2", "webdisk", "autodiscover"
]

help_menu = f"""
╔════════════════════════[Help Menu]════════════════════════════╗
╠═══╦═════════════════════[ General ]═══════════════════════════╣
║   ╠ [help] (h)        Shows this menu.                        ║
║   ╠ [clear] (cls)     Clears the screen.                      ║
║   ╚ [exit] (quit, q)  Exits the application.                  ║
╠═══╦═════════════════[ General 2 ]═════════════════════════════╣
║   ╠ [ip lookup] (ip)   Lookup IP/Domain geo/ISP.              ║
║   ╠ [whois]            Lookup domain registration info.       ║
║   ╠ [dns lookup] (dns)  Query DNS records (A,MX,TXT...).      ║
║   ╠ [sub enum]         Basic subdomain enumeration.           ║
║   ╚ [ping]             Send ICMP Echo requests.               ║
╠═══╦════════════════════[ Scanning ]═══════════════════════════╣
║   ╚ [port scan] (pscan) Basic TCP port scanner.               ║
╠═══╦══════════════════════[ Web ]══════════════════════════════╣
║   ╠ [headers]          Fetch HTTP headers from a URL.         ║
║   ╠ [copy website] (clone) Basic website cloner (HTML+assets) ║
║   ╚ [web crawl] (crawl)  Basic web crawler (find links).      ║
╠═══╦══════════════════[ OSINT / Misc ]═════════════════════════╣
║   ╠ [roblox user] (rluser) Lookup Roblox User (User/URL).     ║
║   ╠ [roblox id] (rlid)   Lookup Roblox User (ID).             ║
║   ╠ [phone lookup] (phone) Lookup phone number info.          ║
║   ╠ [social scan] (social) Check username on platforms.       ║
║   ╚ [mail lookup] (email)  Email OSINT (HIBP link, etc.)      ║
╠═══╦════════════════════[ Utilities ]══════════════════════════╣
║   ╠ [hash]             Generate MD5, SHA1, SHA256 hash.       ║
║   ╠ [base64] (b64)      Encode/Decode Base64 string.          ║
║   ╠ [rand ip]          Generate random public IPv4 addr.      ║
║   ╠ [speed test] (speed)  Test internet connection speed.     ║
║   ╠ [pass gen] (pwgen)  Generate random secure password.      ║
║   ╠ [qr gen]           Generate QR code from text/URL.        ║
║   ╠ [encrypt]          Encrypt a file (AES).                  ║
║   ╚ [decrypt]          Decrypt a file (AES).                  ║
╚═══════════════════════════════════════════════════════════════╝
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_success(message): print(f"{green}[+] {message}{reset_color}")
def print_error(message): print(f"{red}[-] {message}{reset_color}")
def print_info(message): print(f"{blue}[*] {message}{reset_color}")
def print_warning(message): print(f"{yellow}[!] {message}{reset_color}")
def print_header(title): print(f"\n{cyan}--- {title} ---{reset_color}")
def print_footer(title): print(f"{cyan}--- End {title} ---{reset_color}\n")

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def add_scheme_if_missing(url, default_scheme="https"):
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = parsed._replace(scheme=default_scheme)
    return urlunparse(parsed)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password.encode('utf-8'), salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    return salt + encrypted_data

def decrypt_file_data(encrypted_data_with_salt: bytes, password: str) -> bytes:
    try:
        salt = encrypted_data_with_salt[:16]
        encrypted_data = encrypted_data_with_salt[16:]
        key = derive_key(password.encode('utf-8'), salt)
        f = Fernet(key)
        return f.decrypt(encrypted_data)
    except InvalidToken:
        print_error("Decryption failed: Invalid password or corrupted data.")
        return None
    except Exception as e:
        print_error(f"Decryption failed: An unexpected error occurred - {e}")
        return None

def get_user_info(identifier):
    user_id = None
    url_pattern = r"roblox\.com(?:/[a-z-]+)?/users/(\d+)"
    match = re.search(url_pattern, identifier)
    try:
        if match:
            user_id = match.group(1)
            print_info(f"Extracted User ID '{user_id}' from URL.")
        elif identifier.isdigit():
            user_id = identifier
            print_info(f"Input is numeric, treating '{identifier}' as User ID.")
        else:
            print_info(f"Input is not numeric or URL, treating as username. Searching for ID for '{identifier}'...")
            search_url = f"https://users.roblox.com/v1/users/search?keyword={identifier}&limit=1"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(search_url, timeout=10, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get('data') and len(data['data']) > 0:
                user_id = data['data'][0]['id']
                found_name = data['data'][0].get('name', 'N/A')
                found_display_name = data['data'][0].get('displayName', 'N/A')
                print_success(f"Found User ID: {user_id} for username '{found_name}' (Display: '{found_display_name}')")
            else:
                print_error(f"Username '{identifier}' not found or no matching user ID could be retrieved.")
                return None

        if user_id:
            user_url = f"https://users.roblox.com/v1/users/{user_id}"
            print_info(f"Fetching user data for ID: {user_id}...")
            user_response = requests.get(user_url, timeout=10, headers=headers)
            user_response.raise_for_status()
            return user_response.json()
        else:
             return None
    except requests.exceptions.Timeout:
        print_error(f"Network error: The request to Roblox API timed out.")
        return None
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else 'N/A'
        if status_code == 404 and user_id:
             print_error(f"User with ID '{user_id}' not found (404 error).")
        elif status_code == 400 and not identifier.isdigit() and not match :
            print_error(f"Error searching for username '{identifier}' (Bad Request - 400). Check the username format.")
        elif status_code == 429:
            print_error(f"Rate limited by Roblox API. Please wait before trying again.")
        elif status_code == 404 and not user_id:
             print_error(f"Username search failed or resource not found (404 error).")
        else:
            print_error(f"HTTP error occurred: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print_error(f"Network error: {e}")
        return None
    except json.JSONDecodeError:
        print_error(f"Error decoding JSON response from Roblox API.")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during Roblox lookup: {e}")
        return None

def get_phone_info(phone_number_str):
    try:
        if not phone_number_str.startswith('+'):
            print_warning(f"Assuming international format. Adding '+' prefix to '{phone_number_str}'.")
            phone_number_str = "+" + phone_number_str
        parsed_number = phonenumbers.parse(phone_number_str, None)
        if not phonenumbers.is_valid_number(parsed_number):
            print_error(f"The phone number '{phone_number_str}' is not valid.")
            return None

        country = geocoder.description_for_number(parsed_number, "en")
        carrier_name = carrier.name_for_number(parsed_number, "en")

        info = {
            "PhoneNumber": phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "Valid": True,
            "Country": country if country else "N/A",
            "Carrier": carrier_name if carrier_name else "N/A",
            "Timezone(s)": list(phonenumbers.time_zones_for_number(parsed_number))
        }
        return info
    except phonenumbers.phonenumberutil.NumberParseException as e:
        print_error(f"Error parsing phone number '{phone_number_str}': {e}. Please include the country code (e.g., +1..., +44..., +48...).")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during phone lookup: {e}")
        return None

def lookup_social_media(username):
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Youtube": f"https://www.youtube.com/@{username}",
        "Facebook": f"https://www.facebook.com/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}"
    }
    found_profiles = {}
    print_info(f"Checking username '{username}' on various platforms...")
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})

    for platform, url in platforms.items():
        try:
            response = session.get(url, timeout=8, allow_redirects=True)
            if 200 <= response.status_code < 300:
                 print_success(f"Possible profile found on {platform}: {response.url}")
                 found_profiles[platform] = response.url
            elif response.status_code == 404:
                 print(f"{red}[-] Not found on {platform}{reset_color}")
            else:
                 print_warning(f"Uncertain status for {platform} (Code: {response.status_code}) at {url}")
        except requests.exceptions.Timeout:
            print_error(f"Timeout checking {platform}")
        except requests.exceptions.RequestException as e:
            print_error(f"Error checking {platform}: {type(e).__name__}")
        except Exception as e:
            print_error(f"Unexpected error checking {platform}: {e}")
        time.sleep(0.1)

    if not found_profiles:
        print_warning(f"No profiles definitively found for username '{username}' on checked platforms.")
        return None
    return found_profiles

def get_ip_info(ip_or_domain):
    target = ip_or_domain
    ip_address = None

    if not validate_ip(target):
        print_info(f"'{target}' is not an IP. Resolving hostname...")
        ip_address = resolve_hostname(target)
        if not ip_address:
            print_error(f"Could not resolve hostname: {target}")
            return None
        print_success(f"Resolved '{target}' to IP: {ip_address}")
        target = ip_address
    else:
        ip_address = target

    api_url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
    print_info(f"Looking up IP info for: {target}...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(api_url, timeout=10, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            result = {k: v for k, v in data.items() if k not in ('status', 'message')}
            return result
        else:
            print_error(f"API Error for {target}: {data.get('message', 'Unknown error from ip-api.com')}")
            return None
    except requests.exceptions.Timeout:
        print_error(f"Network error: The request to ip-api.com timed out for {target}.")
        return None
    except requests.exceptions.HTTPError as e:
        print_error(f"HTTP error occurred while contacting ip-api.com for {target}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print_error(f"Network error while contacting ip-api.com for {target}: {e}")
        return None
    except json.JSONDecodeError:
        print_error(f"Error decoding JSON response from ip-api.com for {target}.")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during IP lookup for {target}: {e}")
        return None

def get_whois_info(domain):
    print_info(f"Looking up WHOIS for domain: {domain}...")
    try:
        if '.' not in domain or ' ' in domain or domain.startswith('.') or domain.endswith('.'):
             print_error(f"Invalid domain format: {domain}")
             return None
        domain_info = whois.whois(domain)
        if not domain_info or not domain_info.text:
             print_warning(f"Could not retrieve significant WHOIS data for '{domain}'. May be unavailable, protected, or domain invalid.")
             return None
        cleaned_info = {}
        if isinstance(domain_info, dict):
            for key, value in domain_info.items():
                 if isinstance(value, list):
                     cleaned_info[key] = [str(item) if hasattr(item, 'isoformat') else item for item in value]
                 elif hasattr(value, 'isoformat'):
                     cleaned_info[key] = str(value)
                 else:
                     cleaned_info[key] = value
            if not cleaned_info.get('domain_name') and not cleaned_info.get('registrar'):
                print_warning(f"Retrieved potentially incomplete WHOIS data for '{domain}'. Raw text might contain more.")
            return cleaned_info
        else:
             print_warning("WHOIS query returned non-dictionary data. Displaying raw text.")
             print(domain_info.text)
             return {"raw_text": domain_info.text}

    except whois.parser.PywhoisError as e:
        if "No match for" in str(e) or "No WHOIS server known for" in str(e):
             print_error(f"WHOIS lookup failed for '{domain}': Domain likely not registered, invalid TLD, or server error.")
        else:
             print_error(f"WHOIS lookup error for '{domain}': {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during WHOIS lookup: {e}")
        return None

def get_dns_records(domain, record_types=['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']):
    print_info(f"Querying DNS records for {domain} (Types: {', '.join(record_types)})...")
    results = {}
    resolver = dns.resolver.Resolver()

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            if answers.rrset is None:
                 print(f"  {yellow}{rtype}:{reset_color} No record found.")
                 continue

            records = []
            for rdata in answers:
                if rtype == 'MX':
                    records.append({'preference': rdata.preference, 'exchange': str(rdata.exchange).rstrip('.')})
                elif rtype == 'TXT':
                    records.append(' '.join(s.decode('utf-8', errors='ignore') for s in rdata.strings))
                elif rtype == 'SOA':
                     records.append({
                         'mname': str(rdata.mname).rstrip('.'),
                         'rname': str(rdata.rname).rstrip('.'),
                         'serial': rdata.serial,
                         'refresh': rdata.refresh,
                         'retry': rdata.retry,
                         'expire': rdata.expire,
                         'minimum': rdata.minimum
                     })
                elif rtype in ['A', 'AAAA', 'NS', 'CNAME']:
                    records.append(str(rdata).rstrip('.'))
                else:
                    records.append(str(rdata))

            if records:
                results[rtype] = records
                print(f"  {green}{rtype}:{reset_color}")
                for rec in records:
                    if isinstance(rec, dict):
                        print(f"    {json.dumps(rec)}")
                    else:
                        print(f"    {rec}")

        except dns.resolver.NXDOMAIN:
            print_error(f"Domain not found (NXDOMAIN): {domain}")
            return None
        except dns.exception.Timeout:
            print_error(f"DNS query timed out for {rtype} record.")
        except dns.resolver.NoNameservers as e:
             print_error(f"No nameservers could be queried for {domain}: {e}")
        except Exception as e:
            print_error(f"Error querying {rtype} record: {type(e).__name__} - {e}")

    if not results:
        print_warning("No DNS records found for the specified types.")
        return None
    return results

open_ports_list = []
scan_lock = threading.Lock()

def port_scan_worker(target_ip, port_queue, timeout):
    while True:
        try:
            port = port_queue.get_nowait()
        except Queue.Empty:
            break

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    with scan_lock:
                        banner = ""
                        try:
                            if port == 80: sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                            elif port == 22: sock.sendall(b'\r\n')
                            banner_bytes = sock.recv(1024)
                            banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                        except (socket.timeout, ConnectionResetError, OSError):
                             pass
                        except Exception as banner_e:
                            pass

                        port_info = f"Port {port} is open"
                        if banner:
                            port_info += f" (Banner: {banner[:60]}{'...' if len(banner)>60 else ''})"
                        print_success(port_info)
                        open_ports_list.append(port)
            except socket.gaierror:
                with scan_lock:
                    if target_ip not in failed_resolutions:
                         print_error(f"Cannot resolve hostname used in worker for {target_ip}")
                         failed_resolutions.add(target_ip)
                port_queue.task_done()
                break
            except OSError as e:
                with scan_lock:
                    print_warning(f"OS Error scanning port {port}: {e}")
            except Exception as e:
                 with scan_lock:
                      print_warning(f"Unexpected error scanning port {port}: {e}")

        port_queue.task_done()

failed_resolutions = set()

def run_port_scan(target, ports_str, threads=DEFAULT_PORT_SCAN_THREADS, timeout=DEFAULT_PORT_SCAN_TIMEOUT):
    global open_ports_list, failed_resolutions
    open_ports_list = []
    failed_resolutions = set()

    target_ip = None
    if not validate_ip(target):
        print_info(f"Resolving hostname '{target}'...")
        target_ip = resolve_hostname(target)
        if not target_ip:
            print_error(f"Could not resolve hostname: {target}")
            return None
        print_success(f"Resolved '{target}' to IP: {target_ip}")
    else:
        target_ip = target

    print_info(f"Starting TCP port scan on {target_ip} (Threads: {threads}, Timeout: {timeout}s)")

    ports_to_scan = []
    if ports_str.lower() == 'common':
        ports_to_scan = COMMON_PORTS
        print_info(f"Scanning common ports: {', '.join(map(str, COMMON_PORTS))}")
    elif ports_str.lower() == 'all':
         ports_to_scan = range(1, 65536)
         print_warning("Scanning all ports (1-65535). This WILL take a long time!")
    else:
        try:
            temp_ports = set()
            parts = ports_str.split(',')
            for part in parts:
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if 1 <= start <= end <= 65535:
                        temp_ports.update(range(start, end + 1))
                    else:
                        raise ValueError(f"Invalid port range: {part}")
                elif part.isdigit():
                     port_num = int(part)
                     if 1 <= port_num <= 65535:
                          temp_ports.add(port_num)
                     else:
                          raise ValueError(f"Invalid port number: {part}")
                else:
                     raise ValueError(f"Invalid port format: {part}")

            if not temp_ports: raise ValueError("No valid ports specified")
            ports_to_scan = sorted(list(temp_ports))
            print_info(f"Scanning {len(ports_to_scan)} specified ports...")

        except ValueError as e:
            print_error(f"Invalid port specification: '{ports_str}'. Use 'common', 'all', range 'X-Y', or comma-separated 'P1,P2'. Error: {e}")
            return None

    start_time = time.time()
    port_queue = Queue()
    for port in ports_to_scan:
        port_queue.put(port)

    thread_list = []
    actual_threads = min(threads, len(ports_to_scan), 200)
    print_info(f"Using {actual_threads} threads...")

    for _ in range(actual_threads):
        thread = threading.Thread(target=port_scan_worker, args=(target_ip, port_queue, timeout), daemon=True)
        thread.start()
        thread_list.append(thread)

    port_queue.join()

    end_time = time.time()
    print_info(f"Port scan finished in {end_time - start_time:.2f} seconds.")

    if open_ports_list:
        open_ports_list.sort()
        print_success(f"Open ports found ({len(open_ports_list)}): {', '.join(map(str, open_ports_list))}")
        return open_ports_list
    else:
        print_warning("No open ports found in the specified range.")
        return []

def get_http_headers(url):
    original_url = url
    url = add_scheme_if_missing(url)
    print_info(f"Fetching headers for: {url} (Original input: {original_url})...")
    try:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1'
        })

        response = session.get(url, timeout=15, allow_redirects=True, stream=True)
        response.close()

        print_success(f"Request URL: {url}")
        print_success(f"Final URL (after redirects): {response.url}")
        print_success(f"Status Code: {response.status_code} {response.reason}")
        print_info("Response Headers:")
        headers_dict = dict(response.headers)
        for key, value in headers_dict.items():
            print(f"  {key}: {value}")
        return headers_dict

    except requests.exceptions.Timeout:
        print_error(f"Request timed out for {url}.")
        return None
    except requests.exceptions.SSLError as e:
         if url.startswith("https://"):
             http_url = url.replace("https://", "http://", 1)
             print_warning(f"SSL Error for {url}. Trying {http_url}...")
             return get_http_headers(http_url)
         else:
             print_error(f"SSL Error for {url}. Cannot fallback to http. Error: {e}")
             return None
    except requests.exceptions.ConnectionError as e:
         print_error(f"Connection Error for {url}. Check network, DNS, or hostname. Error: {e}")
         return None
    except requests.exceptions.RequestException as e:
        print_error(f"Error fetching headers for {url}: {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred fetching headers: {e}")
        return None

def enumerate_subdomains(domain, wordlist=SUBDOMAIN_WORDLIST):
    print_info(f"Starting basic subdomain enumeration for: {domain}")
    if not wordlist:
         print_warning("Wordlist is empty. Cannot perform subdomain enumeration.")
         return None
    print_info(f"Using {len(wordlist)} common subdomain prefixes.")
    found_subdomains = {}
    lock = threading.Lock()
    q = Queue()

    for sub in wordlist:
        q.put(f"{sub}.{domain}")

    resolved_count = 0

    def worker():
        nonlocal resolved_count
        while not q.empty():
            subdomain = q.get()
            try:
                socket.setdefaulttimeout(1.5)
                ip_address = socket.gethostbyname(subdomain)
                with lock:
                    print_success(f"Found: {subdomain} -> {ip_address}")
                    found_subdomains[subdomain] = ip_address
                    resolved_count += 1
            except socket.gaierror:
                pass
            except socket.timeout:
                 with lock: print_warning(f"Timeout resolving {subdomain}")
            except Exception as e:
                 with lock: print_error(f"Error resolving {subdomain}: {e}")
            finally:
                q.task_done()
                socket.setdefaulttimeout(None)

    threads = []
    num_threads = min(20, q.qsize())
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    q.join()

    if not found_subdomains:
        print_warning(f"No subdomains found using the basic wordlist for {domain}.")
        return None

    print_info(f"Subdomain enumeration finished. Found {resolved_count} active subdomains.")
    return found_subdomains

def calculate_hashes(text):
    print_info(f"Calculating hashes for input text ({len(text)} bytes)...")
    results = {
        "Input Text": text,
        "MD5": hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest(),
        "SHA1": hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest(),
        "SHA256": hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest(),
        "SHA512": hashlib.sha512(text.encode('utf-8', errors='ignore')).hexdigest()
    }
    max_display_len = 100
    display_text = text if len(text) <= max_display_len else text[:max_display_len] + "..."
    print(f"  {white}Input:{reset_color}  {display_text}")
    print(f"  {green}MD5:{reset_color}    {results['MD5']}")
    print(f"  {green}SHA1:{reset_color}   {results['SHA1']}")
    print(f"  {green}SHA256:{reset_color} {results['SHA256']}")
    print(f"  {green}SHA512:{reset_color} {results['SHA512']}")
    return results

def process_base64(text, mode='encode'):
    try:
        if mode == 'encode':
            print_info("Encoding to Base64...")
            encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            print_success(f"Encoded: {encoded}")
            return encoded
        elif mode == 'decode':
            print_info("Decoding from Base64...")
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', text):
                 print_warning("Input doesn't look like standard Base64. Attempting decode anyway.")
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)

            decoded_bytes = base64.b64decode(text.encode('utf-8'))
            try:
                 decoded_str = decoded_bytes.decode('utf-8')
                 print_success(f"Decoded (UTF-8): {decoded_str}")
                 return decoded_str
            except UnicodeDecodeError:
                 print_warning("Decoded data is not valid UTF-8 text.")
                 print_info(f"Decoded bytes (hex): {decoded_bytes.hex()}")
                 return decoded_bytes
        else:
            print_error("Invalid Base64 mode. Use 'encode' or 'decode'.")
            return None
    except base64.binascii.Error as e:
        print_error(f"Base64 Error: {e}. Ensure input is valid Base64 for decoding (check characters, padding).")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during Base64 processing: {e}")
        return None

def copy_website(url, output_dir="website_copy"):
    print_header(f"Website Cloner ({url})")
    print_warning("This is a BASIC cloner. Complex sites, JS-heavy sites, or sites requiring login will likely NOT be fully copied.")
    print_warning("Use responsibly and only on sites you have permission to copy.")

    original_url = url
    url = add_scheme_if_missing(url)
    parsed_base_url = urlparse(url)
    base_domain = parsed_base_url.netloc

    if os.path.exists(output_dir):
        overwrite = input(f"{yellow}Output directory '{output_dir}' already exists. Overwrite? (y/N): {reset_color}").strip().lower()
        if overwrite == 'y':
            try:
                shutil.rmtree(output_dir)
                print_info(f"Removed existing directory: {output_dir}")
            except OSError as e:
                print_error(f"Failed to remove existing directory '{output_dir}': {e}")
                return
        else:
            print_info("Aborting website copy.")
            return

    try:
        os.makedirs(output_dir, exist_ok=True)
        print_info(f"Created output directory: {output_dir}")
    except OSError as e:
        print_error(f"Failed to create output directory '{output_dir}': {e}")
        return

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})

    try:
        print_info(f"Fetching main page: {url}")
        response = session.get(url, timeout=20, allow_redirects=True)
        response.raise_for_status()
        final_url = response.url
        parsed_final_url = urlparse(final_url)

        path_part = parsed_final_url.path.strip('/')
        if not path_part or path_part.endswith('/'):
            filename = "index.html"
        else:
            filename = os.path.basename(path_part)
            if '.' not in filename: filename += ".html"

        dir_path = os.path.join(output_dir, os.path.dirname(path_part))
        os.makedirs(dir_path, exist_ok=True)
        html_save_path = os.path.join(dir_path, filename)
        soup = BeautifulSoup(response.content, 'lxml')
        asset_tags = soup.find_all(['img', 'link', 'script'])
        downloaded_assets = set()

        for tag in asset_tags:
            attr = None
            if tag.name == 'img' and tag.has_attr('src'): attr = 'src'
            elif tag.name == 'link' and tag.has_attr('href'): attr = 'href'
            elif tag.name == 'script' and tag.has_attr('src'): attr = 'src'
            else: continue

            asset_url = tag[attr]
            if not asset_url or asset_url.startswith('data:') or asset_url.startswith('#') or asset_url.startswith('javascript:'):
                continue

            absolute_asset_url = urljoin(final_url, asset_url)
            parsed_asset_url = urlparse(absolute_asset_url)

            if parsed_asset_url.netloc != parsed_final_url.netloc:
                 print_warning(f"Skipping external asset: {absolute_asset_url}")
                 continue

            asset_path = parsed_asset_url.path.lstrip('/')
            local_asset_path_rel = asset_path
            local_asset_path_abs = os.path.join(output_dir, local_asset_path_rel)
            local_asset_dir = os.path.dirname(local_asset_path_abs)
            os.makedirs(local_asset_dir, exist_ok=True)

            if absolute_asset_url not in downloaded_assets:
                try:
                    print_info(f"Downloading asset: {absolute_asset_url}")
                    asset_response = session.get(absolute_asset_url, timeout=15, stream=True)
                    asset_response.raise_for_status()

                    with open(local_asset_path_abs, 'wb') as f:
                        for chunk in asset_response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    downloaded_assets.add(absolute_asset_url)
                    print_success(f"Saved asset to: {local_asset_path_rel}")

                except requests.exceptions.RequestException as e:
                    print_error(f"Failed to download asset {absolute_asset_url}: {e}")
                except IOError as e:
                     print_error(f"Failed to save asset {local_asset_path_rel}: {e}")
                except Exception as e:
                     print_error(f"Unexpected error processing asset {absolute_asset_url}: {e}")

            html_dir_abs = os.path.dirname(html_save_path)
            try:
                 relative_path_to_asset = os.path.relpath(local_asset_path_abs, start=html_dir_abs)
                 tag[attr] = relative_path_to_asset.replace(os.sep, '/')
            except ValueError:
                 print_warning(f"Could not determine relative path for asset {local_asset_path_rel}. Keeping original.")
                 tag[attr] = local_asset_path_rel.replace(os.sep, '/')

        print_info(f"Saving modified HTML to: {html_save_path}")
        with open(html_save_path, 'w', encoding='utf-8') as f:
            f.write(str(soup))

        print_success(f"Website basic copy finished. Files saved in '{output_dir}'. Check {html_save_path}")

    except requests.exceptions.Timeout:
        print_error(f"Request timed out for main page {url}.")
    except requests.exceptions.HTTPError as e:
         print_error(f"HTTP Error fetching main page {url}: {e}")
    except requests.exceptions.RequestException as e:
        print_error(f"Error fetching main page {url}: {e}")
    except IOError as e:
         print_error(f"Error saving HTML file {html_save_path}: {e}")
    except Exception as e:
        print_error(f"An unexpected error occurred during website copy: {e}")
        import traceback
        traceback.print_exc()

    print_footer(f"Website Cloner ({original_url})")

def generate_random_ip():
    private_ranges = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('0.0.0.0/8'),
        ipaddress.ip_network('224.0.0.0/4'),
        ipaddress.ip_network('240.0.0.0/4')
    ]
    while True:
        ip_int = random.randint(0, 2**32 - 1)
        ip = ipaddress.ip_address(ip_int)
        if ip.version == 4 and ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_loopback:
             is_private = False
             for net in private_ranges:
                 if ip in net:
                     is_private = True
                     break
             if not is_private:
                 return str(ip)

def ping_host(host, count=4):
    print_info(f"Pinging {host} ({count} times)...")
    param = '-n' if os.name == 'nt' else '-c'
    command = ["ping", param, str(count), host]
    try:
        result = pythonping.ping(host, count=count, verbose=True, timeout=2)

        print_info("Ping Summary:")
        print(f"  Packets Sent: {count}")
        print(f"  Packets Received: {len(result)}")
        print(f"  Packet Loss: {100 - (len(result)/count * 100):.2f}%")
        if result.rtt_avg_ms: print(f"  Average RTT: {result.rtt_avg_ms:.2f} ms")
        if result.rtt_min_ms: print(f"  Min RTT: {result.rtt_min_ms:.2f} ms")
        if result.rtt_max_ms: print(f"  Max RTT: {result.rtt_max_ms:.2f} ms")

        return result.success

    except PermissionError:
         print_error("Permission denied. Ping often requires root/administrator privileges, especially for detailed stats.")
         print_warning("Attempting fallback using system ping (less detailed output)...")
         try:
             exit_code = os.system(f"ping {param} {count} {host}")
             if exit_code == 0:
                 print_success(f"System ping for {host} seems successful (basic check).")
                 return True
             else:
                 print_error(f"System ping for {host} failed (exit code: {exit_code}). Host may be down or unreachable.")
                 return False
         except Exception as ose:
              print_error(f"Fallback system ping failed: {ose}")
              return False
    except Exception as e:
        print_error(f"An error occurred during ping: {e}")
        if "Cannot resolve" in str(e) or "Name or service not known" in str(e):
             print_error(f"Could not resolve hostname: {host}")
        return False

def run_speed_test():
    print_info("Running internet speed test... This may take a minute.")
    try:
        st = speedtest.Speedtest()
        print_info("Finding best server...")
        st.get_best_server()
        server_info = st.results.server
        print_info(f"Testing against: {server_info['sponsor']} ({server_info['name']}, {server_info['country']})")

        print_info("Testing download speed...")
        download_speed_bps = st.download()
        download_speed_mbps = download_speed_bps / 1_000_000

        print_info("Testing upload speed...")
        upload_speed_bps = st.upload()
        upload_speed_mbps = upload_speed_bps / 1_000_000

        ping = st.results.ping

        print_success("Speed Test Results:")
        print(f"  Ping: {ping:.2f} ms")
        print(f"  Download: {download_speed_mbps:.2f} Mbps")
        print(f"  Upload: {upload_speed_mbps:.2f} Mbps")

        results = {
            'ping_ms': ping,
            'download_mbps': download_speed_mbps,
            'upload_mbps': upload_speed_mbps,
            'server': server_info
        }
        return results

    except speedtest.SpeedtestException as e:
        print_error(f"Speed test failed: {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during speed test: {e}")
        return None

def generate_password(length=16, use_lowercase=True, use_uppercase=True, use_digits=True, use_symbols=True):
    characters = ""
    if use_lowercase: characters += string.ascii_lowercase
    if use_uppercase: characters += string.ascii_uppercase
    if use_digits: characters += string.digits
    if use_symbols: characters += string.punctuation

    if not characters:
        print_error("Cannot generate password: No character types selected.")
        return None

    length = max(8, min(length, 128))

    password_list = []
    if use_lowercase: password_list.append(random.choice(string.ascii_lowercase))
    if use_uppercase: password_list.append(random.choice(string.ascii_uppercase))
    if use_digits: password_list.append(random.choice(string.digits))
    if use_symbols: password_list.append(random.choice(string.punctuation))

    remaining_length = length - len(password_list)
    if remaining_length > 0:
        password_list.extend(random.choice(characters) for _ in range(remaining_length))

    random.shuffle(password_list)
    password = "".join(password_list)

    return password

def generate_qr_code(data, filename="qrcode.png"):
    print_info(f"Generating QR code for data: '{data[:50]}{'...' if len(data)>50 else ''}'")
    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        if not any(filename.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.bmp']):
             filename += ".png"
             print_warning(f"Appending .png extension to filename: {filename}")

        img.save(filename)
        print_success(f"QR Code saved successfully as: {filename}")
        return filename
    except Exception as e:
        print_error(f"Failed to generate QR code: {e}")
        return None

def web_crawl(start_url, max_depth=1, stay_on_domain=True, max_pages=50):
    print_header(f"Web Crawler ({start_url})")
    print_warning("This is a VERY basic crawler. Use with extreme caution and respect robots.txt (implementation not included here).")
    print_warning("Crawling can heavily load servers. Ensure you have permission.")

    start_url = add_scheme_if_missing(start_url)
    base_url_parsed = urlparse(start_url)
    target_domain = base_url_parsed.netloc

    if not target_domain:
        print_error("Invalid start URL or could not parse domain.")
        return None

    urls_to_visit = Queue()
    urls_to_visit.put((start_url, 0))
    visited_urls = {start_url}
    found_links = {start_url}
    pages_crawled = 0

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; PythonCrawler/0.1; +http://example.com/bot)'})

    print_info(f"Starting crawl from: {start_url} (Max Depth: {max_depth}, Domain Lock: {stay_on_domain}, Max Pages: {max_pages})")

    while not urls_to_visit.empty() and pages_crawled < max_pages:
        current_url, current_depth = urls_to_visit.get()

        if current_depth > max_depth:
            continue

        print_info(f"Crawling [Depth {current_depth}]: {current_url}")
        pages_crawled += 1

        try:
            time.sleep(0.3)
            response = session.get(current_url, timeout=10, allow_redirects=True)
            response.raise_for_status()

            content_type = response.headers.get('content-type', '').lower()
            if 'html' not in content_type:
                 print_warning(f"Skipping non-HTML content at {current_url} ({content_type})")
                 continue

            final_url = response.url
            final_url_parsed = urlparse(final_url)

            if stay_on_domain and final_url_parsed.netloc != target_domain:
                 print_warning(f"Redirected off-domain, stopping crawl for this path: {final_url}")
                 continue

            soup = BeautifulSoup(response.content, 'lxml')

            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(final_url, href)
                parsed_absolute_url = urlparse(absolute_url)

                clean_url = urlunparse(parsed_absolute_url._replace(fragment=""))

                if parsed_absolute_url.scheme not in ['http', 'https']:
                    continue

                if stay_on_domain and parsed_absolute_url.netloc != target_domain:
                    found_links.add(clean_url)
                    continue

                if clean_url not in visited_urls:
                    if current_depth + 1 <= max_depth:
                        urls_to_visit.put((clean_url, current_depth + 1))
                    visited_urls.add(clean_url)
                    found_links.add(clean_url)

        except requests.exceptions.Timeout:
            print_error(f"Timeout crawling: {current_url}")
        except requests.exceptions.HTTPError as e:
            print_error(f"HTTP Error {e.response.status_code} crawling: {current_url}")
        except requests.exceptions.RequestException as e:
            print_error(f"Request Error crawling {current_url}: {e}")
        except Exception as e:
             print_error(f"Unexpected error crawling {current_url}: {e}")

    print_info(f"Crawler finished. Crawled {pages_crawled} pages. Found {len(found_links)} unique links.")
    print_footer(f"Web Crawler ({start_url})")
    return sorted(list(found_links))

def mail_lookup(email):
    print_header(f"Email OSINT ({email})")

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print_error("Invalid email format.")
        return

    domain = email.split('@')[-1]
    print_info(f"Domain: {domain}")

    print_info("Checking MX Records...")
    get_dns_records(domain, record_types=['MX'])

    print_info("Checking HaveIBeenPwned (Manual Check Recommended):")
    print(f" - Visit: {white}https://haveibeenpwned.com/{reset_color} and enter the email.")

    print_info("Checking Business Email Verification Services (Examples):")
    print(f" - {white}Hunter.io:{reset_color} (Requires API key for programmatic checks) Checks if email domain is used for professional emails.")
    print(f" - {white}Skymem.info:{reset_color} (Public search engine for email addresses found online)")
    print(f"   - Search: https://skymem.info/srch?q={email}")


    print_info("Consider Google Dorking:")
    print(f" - \"{email}\"")
    print(f" - site:linkedin.com \"{email}\"")

    print_footer(f"Email OSINT ({email})")


def handle_help(): print(help_menu)
def handle_exit(): print_warning("Exiting... Stay ethical!"); sys.exit()

def handle_roblox_user():
    print_header("Roblox User Lookup (Username/URL)")
    identifier = input(f"{white}Enter Roblox Username or Profile URL: {reset_color}").strip()
    if not identifier: print_error("Identifier cannot be empty."); return
    user_info = get_user_info(identifier)
    if user_info: print(json.dumps(user_info, indent=4, ensure_ascii=False))
    print_footer("Roblox User Lookup")

def handle_roblox_id():
    print_header("Roblox ID Lookup")
    identifier = input(f"{white}Enter Roblox User ID: {reset_color}").strip()
    if not identifier: print_error("User ID cannot be empty."); return
    if not identifier.isdigit(): print_error("Invalid input. Please enter a numeric User ID."); return
    user_info = get_user_info(identifier)
    if user_info: print(json.dumps(user_info, indent=4, ensure_ascii=False))
    print_footer("Roblox ID Lookup")

def handle_phone_lookup():
    print_header("Phone Number OSINT")
    phone_num = input(f"{white}Enter Phone Number (e.g., +14155552671): {reset_color}").strip()
    if not phone_num: print_error("Phone number cannot be empty."); return
    phone_info = get_phone_info(phone_num)
    if phone_info: print(json.dumps(phone_info, indent=4))
    print_footer("Phone Number OSINT")

def handle_social_media():
    print_header("Social Media Username Check")
    sm_username = input(f"{white}Enter Username to check: {reset_color}").strip()
    if not sm_username: print_error("Username cannot be empty."); return
    found_accounts = lookup_social_media(sm_username)
    if found_accounts:
         print("\n--- Summary of Possible Profiles ---")
         for platform, url in found_accounts.items():
              print(f" - {platform}: {url}")
         print("---------------------------------")
    print_footer("Social Media Username Check")

def handle_ip_lookup():
    print_header("IP/Domain Geo & ISP Lookup")
    ip_address = input(f"{white}Enter IP Address or Domain Name: {reset_color}").strip()
    if not ip_address: print_error("IP Address or Domain Name cannot be empty."); return
    ip_info = get_ip_info(ip_address)
    if ip_info: print(json.dumps(ip_info, indent=4, ensure_ascii=False))
    print_footer("IP/Domain Geo & ISP Lookup")

def handle_whois_lookup():
    print_header("WHOIS Domain Lookup")
    domain_name = input(f"{white}Enter Domain Name: {reset_color}").strip().lower()
    if not domain_name: print_error("Domain name cannot be empty."); return
    whois_data = get_whois_info(domain_name)
    if whois_data: print(json.dumps(whois_data, indent=4, default=str))
    print_footer("WHOIS Domain Lookup")

def handle_dns_lookup():
    print_header("DNS Record Lookup")
    domain_name = input(f"{white}Enter Domain Name: {reset_color}").strip().lower()
    if not domain_name: print_error("Domain name cannot be empty."); return
    record_types_str = input(f"{white}Enter record types (comma-separated, e.g., A,MX,TXT, default all): {reset_color}").strip().upper()
    record_types = [rt.strip() for rt in record_types_str.split(',')] if record_types_str else ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    valid_types = {'A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR', 'CAA'}
    record_types = [rt for rt in record_types if rt in valid_types]
    if not record_types:
         print_warning("No valid record types specified or default list used. Using default.")
         record_types=['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']

    get_dns_records(domain_name, record_types=record_types)
    print_footer("DNS Record Lookup")

def handle_port_scan():
    print_header("TCP Port Scanner")
    target = input(f"{white}Enter Target IP or Hostname: {reset_color}").strip()
    if not target: print_error("Target cannot be empty."); return
    ports_input = input(f"{white}Enter Ports ('common', 'all', range 'X-Y', or 'P1,P2'): {reset_color}").strip().lower()
    if not ports_input: print_warning("No ports specified, defaulting to 'common'."); ports_input = 'common'
    run_port_scan(target, ports_input)
    print_footer("TCP Port Scanner")

def handle_http_headers():
    print_header("HTTP Header Viewer")
    url = input(f"{white}Enter URL (e.g., https://example.com): {reset_color}").strip()
    if not url: print_error("URL cannot be empty."); return
    get_http_headers(url)
    print_footer("HTTP Header Viewer")

def handle_sub_enum():
    print_header("Basic Subdomain Enumeration")
    domain = input(f"{white}Enter Domain Name (e.g., example.com): {reset_color}").strip().lower()
    if not domain: print_error("Domain name cannot be empty."); return
    found = enumerate_subdomains(domain)
    print_footer("Basic Subdomain Enumeration")

def handle_hash():
    print_header("Hashing Utility (MD5, SHA1, SHA256, SHA512)")
    text_to_hash = input(f"{white}Enter text to hash: {reset_color}")
    calculate_hashes(text_to_hash)
    print_footer("Hashing Utility")

def handle_base64():
    print_header("Base64 Encode/Decode")
    mode = input(f"{white}Choose mode [encode/decode]: {reset_color}").strip().lower()
    if mode not in ['encode', 'decode']: print_error("Invalid mode."); return
    text_to_process = input(f"{white}Enter text to {mode}: {reset_color}").strip()
    if mode == 'decode' and not text_to_process: print_error("Input cannot be empty for decoding."); return
    process_base64(text_to_process, mode)
    print_footer("Base64 Encode/Decode")

def handle_copy_website():
    print_header("Basic Website Cloner")
    url = input(f"{white}Enter URL of website to copy: {reset_color}").strip()
    if not url: print_error("URL cannot be empty."); return
    output_dir = input(f"{white}Enter output directory name (default: website_copy): {reset_color}").strip() or "website_copy"
    copy_website(url, output_dir)

def handle_rand_ip():
    print_header("Random IP Generator")
    random_ip = generate_random_ip()
    print_success(f"Generated Random Public IPv4: {random_ip}")
    print_footer("Random IP Generator")

def handle_ping():
    print_header("Ping Utility")
    host = input(f"{white}Enter IP address or hostname to ping: {reset_color}").strip()
    if not host: print_error("Host cannot be empty."); return
    try:
        count_str = input(f"{white}Enter number of pings (default 4): {reset_color}").strip()
        count = int(count_str) if count_str.isdigit() and int(count_str) > 0 else 4
    except ValueError:
        print_warning("Invalid count, using default 4.")
        count = 4
    ping_host(host, count=count)
    print_footer("Ping Utility")

def handle_speed_test():
    print_header("Internet Speed Test")
    run_speed_test()
    print_footer("Internet Speed Test")

def handle_pass_gen():
    print_header("Password Generator")
    try:
        length_str = input(f"{white}Enter desired password length (8-128, default 16): {reset_color}").strip()
        length = int(length_str) if length_str.isdigit() else 16
        length = max(8, min(length, 128))
    except ValueError:
        length = 16
        print_warning("Invalid length, using default 16.")

    def ask_yes_no(prompt, default_yes=True):
         answer = input(f"{white}{prompt} (Y/n): {reset_color}" if default_yes else f"{white}{prompt} (y/N): {reset_color}").strip().lower()
         if default_yes: return answer != 'n'
         else: return answer == 'y'

    use_lower = ask_yes_no("Include lowercase letters?", True)
    use_upper = ask_yes_no("Include uppercase letters?", True)
    use_digits = ask_yes_no("Include digits?", True)
    use_symbols = ask_yes_no("Include symbols?", True)

    if not any([use_lower, use_upper, use_digits, use_symbols]):
         print_error("At least one character type must be selected.")
         print_footer("Password Generator")
         return

    password = generate_password(length, use_lower, use_upper, use_digits, use_symbols)
    if password:
        print_success(f"Generated Password ({length} chars): {password}")
    print_footer("Password Generator")

def handle_qr_gen():
    print_header("QR Code Generator")
    data = input(f"{white}Enter text or URL to encode: {reset_color}").strip()
    if not data: print_error("Data cannot be empty."); return
    filename = input(f"{white}Enter output filename (e.g., my_qr.png, default qrcode.png): {reset_color}").strip() or "qrcode.png"
    generate_qr_code(data, filename)
    print_footer("QR Code Generator")

def handle_web_crawl():
    print_header("Basic Web Crawler")
    start_url = input(f"{white}Enter starting URL: {reset_color}").strip()
    if not start_url: print_error("Start URL cannot be empty."); return

    try:
        depth_str = input(f"{white}Enter max crawl depth (default 1): {reset_color}").strip()
        max_depth = int(depth_str) if depth_str.isdigit() else 1
        max_depth = max(0, min(max_depth, 5))
    except ValueError: max_depth = 1; print_warning("Invalid depth, using 1.")

    try:
        pages_str = input(f"{white}Enter max pages to crawl (default 50): {reset_color}").strip()
        max_pages = int(pages_str) if pages_str.isdigit() else 50
        max_pages = max(1, min(max_pages, 500))
    except ValueError: max_pages = 50; print_warning("Invalid max pages, using 50.")

    stay_domain_ans = input(f"{white}Stay on starting domain? (Y/n): {reset_color}").strip().lower()
    stay_on_domain = stay_domain_ans != 'n'

    found_links = web_crawl(start_url, max_depth, stay_on_domain, max_pages)
    if found_links:
         save_choice = input(f"{yellow}Save found links to file? (y/N): {reset_color}").strip().lower()
         if save_choice == 'y':
             out_file = f"crawl_links_{urlparse(start_url).netloc}.txt"
             try:
                 with open(out_file, 'w', encoding='utf-8') as f:
                     for link in found_links:
                         f.write(link + '\n')
                 print_success(f"Links saved to {out_file}")
             except IOError as e:
                 print_error(f"Error saving links file: {e}")

def handle_mail_lookup():
    print_header("Email OSINT")
    email = input(f"{white}Enter email address to check: {reset_color}").strip()
    if not email: print_error("Email cannot be empty."); return
    mail_lookup(email)

def handle_encrypt_file():
    print_header("File Encryption (AES)")
    filepath = input(f"{white}Enter path to file to encrypt: {reset_color}").strip()
    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}"); return

    password = input(f"{white}Enter encryption password: {reset_color}")
    if not password: print_error("Password cannot be empty."); return
    password_confirm = input(f"{white}Confirm password: {reset_color}")
    if password != password_confirm:
        print_error("Passwords do not match."); return

    try:
        print_info(f"Reading file: {filepath}")
        with open(filepath, 'rb') as f:
            data = f.read()

        print_info("Encrypting data...")
        encrypted_data = encrypt_file_data(data, password)

        output_filename = filepath + ".enc"
        print_info(f"Writing encrypted file: {output_filename}")
        with open(output_filename, 'wb') as f:
            f.write(encrypted_data)

        print_success(f"File encrypted successfully: {output_filename}")
        print_warning("IMPORTANT: Remember your password! It cannot be recovered.")

    except IOError as e:
        print_error(f"File IO Error: {e}")
    except Exception as e:
        print_error(f"Encryption failed: {e}")
    print_footer("File Encryption")

def handle_decrypt_file():
    print_header("File Decryption (AES)")
    filepath = input(f"{white}Enter path to file to decrypt (.enc): {reset_color}").strip()

    if not os.path.isfile(filepath):
        print_error(f"Encrypted file not found: {filepath}"); return
    if not filepath.lower().endswith(".enc"):
        print_warning("Filename does not end with '.enc'. Attempting anyway.")

    password = input(f"{white}Enter decryption password: {reset_color}")
    if not password: print_error("Password cannot be empty."); return

    try:
        print_info(f"Reading encrypted file: {filepath}")
        with open(filepath, 'rb') as f:
            encrypted_data_with_salt = f.read()

        print_info("Decrypting data...")
        decrypted_data = decrypt_file_data(encrypted_data_with_salt, password)

        if decrypted_data is not None:
            if filepath.lower().endswith(".enc"):
                output_filename = filepath[:-4]
            else:
                output_filename = filepath + ".dec"
            if os.path.exists(output_filename):
                 overwrite = input(f"{yellow}Output file '{output_filename}' already exists. Overwrite? (y/N): {reset_color}").strip().lower()
                 if overwrite != 'y':
                      print_info("Decryption aborted to avoid overwriting.")
                      print_footer("File Decryption")
                      return

            print_info(f"Writing decrypted file: {output_filename}")
            with open(output_filename, 'wb') as f:
                f.write(decrypted_data)
            print_success(f"File decrypted successfully: {output_filename}")

    except IOError as e:
        print_error(f"File IO Error: {e}")
    except Exception as e:
        print_error(f"Decryption failed: {e}")
    print_footer("File Decryption")

commands = {
    "help": handle_help, "h": handle_help,
    "exit": handle_exit, "quit": handle_exit, "q": handle_exit,
    "clear": clear_screen, "cls": clear_screen,

    "ip lookup": handle_ip_lookup, "ip": handle_ip_lookup,
    "whois": handle_whois_lookup,
    "dns lookup": handle_dns_lookup, "dns": handle_dns_lookup,
    "sub enum": handle_sub_enum,
    "ping": handle_ping,

    "port scan": handle_port_scan, "pscan": handle_port_scan,

    "headers": handle_http_headers,
    "copy website": handle_copy_website, "clone": handle_copy_website,
    "web crawl": handle_web_crawl, "crawl": handle_web_crawl,

    "roblox user": handle_roblox_user, "rluser": handle_roblox_user,
    "roblox id": handle_roblox_id, "rlid": handle_roblox_id,
    "phone lookup": handle_phone_lookup, "phone": handle_phone_lookup,
    "social scan": handle_social_media, "social": handle_social_media,
    "mail lookup": handle_mail_lookup, "email": handle_mail_lookup,

    "hash": handle_hash,
    "base64": handle_base64, "b64": handle_base64,
    "rand ip": handle_rand_ip,
    "speed test": handle_speed_test, "speed": handle_speed_test,
    "pass gen": handle_pass_gen, "pwgen": handle_pass_gen,
    "qr gen": handle_qr_gen,
    "encrypt": handle_encrypt_file,
    "decrypt": handle_decrypt_file,
}

if __name__ == "__main__":
    clear_screen()
    print(f"""{m_color}
          __________  __________________    __    __    ______
         / ____/ __ \\/  _/ ___/_  __/   |  / /   / /   / __  /
        / /   / /_/ // / \__ \\ / / / /| | / /   / /   / / / /
       / /___/ _, _// / ___/ // / / ___ |/ /___/ /___/ /_/ /
       \____/_/ |_/___//____//_/ /_/  |_/_____/_____/\\____/
{cyan}            --[MOUNTAINS MULTITOOLS]--{reset_color}
{cyan}                 --[MOUNTAIN 2]--{reset_color}""")

    print(f"{white}Type 'help' for available commands.{reset_color}\n")

    while True:
        try:
            user_input = input(f"{m_color}[Cristallo]>_{white} ")


            command_func = commands.get(user_input)
            if command_func:
                if user_input in ['clear', 'cls']:
                    clear_screen()
                else:
                    command_func()
            elif user_input:
                print_error(f"Invalid command: '{user_input}'. Type 'help' for options.")

        except KeyboardInterrupt:
            print("\n")
            handle_exit()
        except EOFError:
             print("\n")
             handle_exit()
