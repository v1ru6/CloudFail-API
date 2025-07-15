#!/usr/bin/env python3
from __future__ import print_function
import argparse
import re
import sys
import socket
import binascii
import datetime
import socks
import requests
import colorama
import os
import win_inet_pton
import platform
from colorama import Fore, Style
from DNSDumpsterAPI import DNSDumpsterAPI
import dns.resolver
import collections
collections.Callable = collections.abc.Callable

colorama.init(autoreset=True)


def print_out(msg, end='\n'):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    line = f"[{ts}] {re.sub(' +', ' ', msg)}"
    print(Style.NORMAL + line + Style.RESET_ALL, end=end)


def ip_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            packed = (
                win_inet_pton.inet_pton(version, ip_address)
                if platform.system().startswith('Windows')
                else socket.inet_pton(version, ip_address)
            )
            return int(binascii.hexlify(packed), 16), (4 if version == socket.AF_INET else 6)
        except Exception:
            pass
    raise ValueError("invalid IP address")


def subnetwork_to_ip_range(subnet):
    try:
        net, length = subnet.split('/')
        length = int(length)
        for version in (socket.AF_INET, socket.AF_INET6):
            bitlen = 32 if version == socket.AF_INET else 128
            try:
                suffix = (1 << (bitlen - length)) - 1
                mask = ((1 << bitlen) - 1) ^ suffix
                packed = socket.inet_pton(version, net)
                low = int(binascii.hexlify(packed), 16) & mask
                return low, low + suffix, (4 if version == socket.AF_INET else 6)
            except Exception:
                pass
    except Exception:
        pass
    raise ValueError("invalid subnetwork")


def ip_in_subnetwork(ip, subnet):
    ip_int, v1 = ip_to_integer(ip)
    low, high, v2 = subnetwork_to_ip_range(subnet)
    if v1 != v2:
        raise ValueError("incompatible IP versions")
    return low <= ip_int <= high


def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing DNS via DNSDumpster API…")
    api = DNSDumpsterAPI(api_key=args.api_key, verbose=False)
    dnsdumpster_domains = set()
    
    try:
        res = api.search(target, page=None, include_map=False)
    except Exception as e:
        print_out(Fore.RED + f"DNSDumpster error: {e}")
        return dnsdumpster_domains

    # Process and display DNSDumpster results
    for rtype in ("a", "ns", "mx", "cname"):
        for entry in res.get(rtype, []):
            host = entry.get("host", "")
            if host:
                dnsdumpster_domains.add(host)
                
            for ipinfo in entry.get("ips", []):
                ip = ipinfo.get("ip", "")
                asn = ipinfo.get("asn", "")
                prov = ipinfo.get("asn_name", "")
                country = ipinfo.get("country", "")
                print_out(
                    Style.BRIGHT
                    + Fore.WHITE
                    + f"[FOUND:{rtype.upper():5}] {host:30}→ {ip:15} {asn:6} {prov:15} {country}"
                )

    for txt in res.get("txt", []):
        print_out(Style.BRIGHT + Fore.WHITE + f"[FOUND:TXT   ] {txt}")
    
    print_out(Fore.CYAN + f"DNSDumpster found {len(dnsdumpster_domains)} unique domains")
    return dnsdumpster_domains


def crimeflare(target):
    print_out(Fore.CYAN + "Scanning Crimeflare DB…")
    hits = []
    with open("data/ipout", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == target:
                hits.append(parts[2])
    if not hits:
        print_out("No Crimeflare results.")
    else:
        for ip in hits:
            print_out(Style.BRIGHT + Fore.WHITE + f"[FOUND:IP    ] {ip}")


def inCloudFlare(ip):
    path = os.path.join(os.getcwd(), "data/cf-subnet.txt")
    with open(path) as f:
        for ln in f:
            if ip_in_subnetwork(ip, ln.strip()):
                return True
    return False


def init(target):
    if not target:
        print_out(Fore.RED + "No target set — exiting")
        sys.exit(1)
    print_out(Fore.CYAN + f"Initializing against {target}…")

    if not os.path.isfile("data/ipout"):
        print_out(Fore.CYAN + "No ipout file — fetching updates")
        update()
        print_out(Fore.CYAN + "ipout created")

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_out(Fore.RED + "Invalid domain — exiting")
        sys.exit(1)

    print_out(Fore.CYAN + f"Resolved {target} → {ip}")
    print_out(Fore.CYAN + "Checking Cloudflare network…")
    try:
        if inCloudFlare(ip):
            print_out(Style.BRIGHT + Fore.GREEN + f"{target} is behind Cloudflare")
        else:
            if args.force:
                # Continue execution even though the target is not behind Cloudflare
                print_out(
                    Fore.YELLOW
                    + f"{target} NOT on Cloudflare — continuing anyway due to --force"
                )
            else:
                print_out(Fore.RED + f"{target} NOT on Cloudflare — quitting")
                sys.exit(0)
    except ValueError:
        print_out(Fore.RED + "IP mismatch error — exiting")
        sys.exit(1)


def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["1.1.1.1", "1.0.0.1"]
    try:
        resolver.resolve("*." + target)
        return True
    except Exception:
        return False


def resolve_subdomain(subdomain):
    """Resolve a subdomain and return IP if successful, None otherwise"""
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None


def check_subdomain(subdomain, target):
    """Check a single subdomain and return result if resolved successfully"""
    # DNS resolution
    ip = resolve_subdomain(subdomain)
    if ip is None:
        return None  # Skip unresolved subdomains
    
    # check Cloudflare
    try:
        is_cf = inCloudFlare(ip)
    except ValueError:
        is_cf = False

    # HTTP probe
    try:
        r = requests.get("http://" + subdomain, timeout=5)
        status = r.status_code
    except Exception:
        status = "ERR"

    color = Fore.RED if is_cf else Fore.GREEN
    tag = "CLOUDFLARE" if is_cf else "OPEN"

    result = {
        'subdomain': subdomain,
        'ip': ip,
        'status': status,
        'is_cf': is_cf,
        'tag': tag,
        'color': color
    }
    
    return result


def subdomain_scan(target, wordlist_file, dnsdumpster_domains, force=False):
    # If wildcard DNS is present, respect --force
    if not force and check_for_wildcard(target):
        print_out(Fore.CYAN + "Wildcard DNS detected — aborting scan (use -F to force)")
        return

    # Load wordlist
    try:
        with open(wordlist_file, "r") as f:
            labels = [l.strip() for l in f if l.strip()]
    except IOError:
        print_out(Fore.RED + f"Cannot open subdomains file '{wordlist_file}' — aborting")
        sys.exit(1)

    # Create full subdomain list from wordlist
    wordlist_subdomains = set()
    for label in labels:
        if label.lower().endswith(target.lower()):
            wordlist_subdomains.add(label)
        else:
            wordlist_subdomains.add(f"{label}.{target}")

    # Combine wordlist subdomains with DNSDumpster results
    all_subdomains = wordlist_subdomains.union(dnsdumpster_domains)
    
    # Filter out duplicates and sort
    all_subdomains = sorted(list(all_subdomains))
    
    total = len(all_subdomains)
    resolved_count = 0
    skipped_count = 0
    
    print_out(Fore.CYAN + f"Scanning {total} subdomains ({len(wordlist_subdomains)} from wordlist + {len(dnsdumpster_domains)} from DNSDumpster)…")

    for idx, subdomain in enumerate(all_subdomains, start=1):
        if total and idx % max(1, total // 100) == 0:
            pct = round(idx / total * 100, 1)
            print_out(Fore.CYAN + f"{pct}% complete ({resolved_count} resolved, {skipped_count} skipped)", end='\r')

        result = check_subdomain(subdomain, target)
        
        if result is None:
            skipped_count += 1
            # Don't print [SKIP:RESOLVE] messages
            continue
        
        resolved_count += 1
        
        # Print the result
        source_tag = "[DNS]" if subdomain in dnsdumpster_domains else "[WRD]"
        print_out(
            Style.BRIGHT
            + Fore.WHITE
            + f"[FOUND:SUB] {source_tag} {result['subdomain']:30} IP: {result['ip']:15} HTTP: {result['status']} "
            + result['color']
            + result['tag']
        )

    print_out(Fore.CYAN + f"Subdomain scan complete. Found {resolved_count} resolved domains, skipped {skipped_count} unresolved.")


def update():
    print_out(Fore.CYAN + "Updating CF and Crimeflare data…")
    if not args.tor:
        cf = requests.get("https://www.cloudflare.com/ips-v4", timeout=10).text
        with open("data/cf-subnet.txt", "w") as fd:
            fd.write(cf)
    else:
        print_out(Fore.RED + "Cannot update CF ranges over TOR")
    ipout = requests.get("https://cf.ozeliurs.com/ipout", timeout=10).text
    with open("data/ipout", "w") as fd:
        fd.write(ipout)


# ---- MAIN ----

logo = r"""
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.5                      by m0rtem
    v1.0.6                      by v1ru6
"""
print(Fore.RED + Style.BRIGHT + logo + Fore.RESET)
print_out("Initializing Enhanced CloudFail — " + datetime.datetime.now().strftime("%d/%m/%Y"))

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target URL", type=str, required=True)
parser.add_argument("-T", "--tor", help="use TOR", action="store_true")
parser.add_argument("-u", "--update", help="update DBs", action="store_true")
parser.add_argument("-k", "--api-key", help="DNSDumpster key", required=True)
parser.add_argument(
    "-s",
    "--subdomains",
    metavar="FILE",
    default="data/subdomains.txt",
    help="path to subdomain list",
)
parser.add_argument(
    "-F",
    "--force",
    action="store_true",
    help="force scan even if wildcard DNS detected or target is not behind Cloudflare",
)
parser.set_defaults(tor=False, update=False)

args = parser.parse_args()

if args.tor:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket
    try:
        sip = requests.get("http://ipinfo.io/ip", timeout=5).text.strip()
        print_out(Fore.WHITE + Style.BRIGHT + "TOR up, IP=" + sip)
    except Exception:
        sys.exit(1)

if args.update:
    update()

try:
    init(args.target)
    dnsdumpster_domains = dnsdumpster(args.target)
    crimeflare(args.target)
    subdomain_scan(args.target, args.subdomains, dnsdumpster_domains, force=args.force)
except KeyboardInterrupt:
    sys.exit(0)
