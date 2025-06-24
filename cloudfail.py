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
    line = f"[{ts}] {re.sub(' +',' ', msg)}"
    print(Style.NORMAL + line + Style.RESET_ALL, end=end)

def ip_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            packed = (win_inet_pton.inet_pton(version, ip_address)
                      if platform.system().startswith('Windows')
                      else socket.inet_pton(version, ip_address))
            return int(binascii.hexlify(packed), 16), (4 if version==socket.AF_INET else 6)
        except:
            pass
    raise ValueError("invalid IP address")

def subnetwork_to_ip_range(subnet):
    try:
        net, length = subnet.split('/')
        length = int(length)
        for version in (socket.AF_INET, socket.AF_INET6):
            bitlen = 32 if version==socket.AF_INET else 128
            try:
                suffix = (1 << (bitlen - length)) - 1
                mask   = ((1 << bitlen) - 1) ^ suffix
                packed = socket.inet_pton(version, net)
                low    = int(binascii.hexlify(packed),16) & mask
                return low, low+suffix, (4 if version==socket.AF_INET else 6)
            except:
                pass
    except:
        pass
    raise ValueError("invalid subnetwork")

def ip_in_subnetwork(ip, subnet):
    ip_int, v1   = ip_to_integer(ip)
    low, high, v2= subnetwork_to_ip_range(subnet)
    if v1!=v2:
        raise ValueError("incompatible IP versions")
    return low <= ip_int <= high

def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing DNS via DNSDumpster API…")
    api = DNSDumpsterAPI(api_key=args.api_key, verbose=False)
    try:
        res = api.search(target, page=None, include_map=False)
    except Exception as e:
        print_out(Fore.RED + f"DNSDumpster error: {e}")
        return

    for rtype in ('a','ns','mx','cname'):
        for entry in res.get(rtype, []):
            host = entry.get('host','')
            for ipinfo in entry.get('ips',[]):
                ip      = ipinfo.get('ip','')
                asn     = ipinfo.get('asn','')
                prov    = ipinfo.get('asn_name','')
                country = ipinfo.get('country','')
                print_out(Style.BRIGHT+Fore.WHITE+
                          f"[FOUND:{rtype.upper():5}] {host:30}→ {ip:15} {asn:6} {prov:15} {country}")

    for txt in res.get('txt', []):
        print_out(Style.BRIGHT+Fore.WHITE+f"[FOUND:TXT   ] {txt}")

def crimeflare(target):
    print_out(Fore.CYAN + "Scanning Crimeflare DB…")
    hits = []
    with open("data/ipout","r") as f:
        for line in f:
            parts = line.split()
            if len(parts)>=3 and parts[1]==target:
                hits.append(parts[2])
    if not hits:
        print_out("No Crimeflare results.")
    else:
        for ip in hits:
            print_out(Style.BRIGHT+Fore.WHITE+f"[FOUND:IP    ] {ip}")

def inCloudFlare(ip):
    path = os.path.join(os.getcwd(),'data/cf-subnet.txt')
    with open(path) as f:
        for ln in f:
            if ip_in_subnetwork(ip, ln.strip()):
                return True
    return False

def init(target):
    if not target:
        print_out(Fore.RED+"No target set — exiting")
        sys.exit(1)
    print_out(Fore.CYAN+f"Initializing against {target}…")

    if not os.path.isfile("data/ipout"):
        print_out(Fore.CYAN+"No ipout file — fetching updates")
        update()
        print_out(Fore.CYAN+"ipout created")

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_out(Fore.RED+"Invalid domain — exiting")
        sys.exit(1)

    print_out(Fore.CYAN+f"Resolved {target} → {ip}")
    print_out(Fore.CYAN+"Checking Cloudflare network…")
    try:
        if inCloudFlare(ip):
            print_out(Style.BRIGHT+Fore.GREEN+f"{target} is behind Cloudflare")
        else:
            print_out(Fore.RED+f"{target} NOT on Cloudflare — quitting")
            sys.exit(0)
    except ValueError:
        print_out(Fore.RED+"IP mismatch error — exiting")
        sys.exit(1)

def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1','1.0.0.1']
    try:
        resolver.resolve('*.'+target)
        return True
    except:
        return False

def subdomain_scan(target, wordlist_file, force=False):
    if not force and check_for_wildcard(target):
        print_out(Fore.CYAN + "Wildcard DNS detected — aborting scan (use -F to force)")
        return

    try:
        with open(wordlist_file,"r") as f:
            labels = [l.strip() for l in f if l.strip()]
    except IOError:
        print_out(Fore.RED+f"Cannot open subdomains file '{wordlist_file}' — aborting")
        sys.exit(1)

    total = len(labels)
    print_out(Fore.CYAN+f"Scanning {total} subdomains from {wordlist_file}…")

    for idx, label in enumerate(labels, start=1):
        if total and idx % max(1, total//100)==0:
            pct = round(idx/total*100,1)
            print_out(Fore.CYAN+f"{pct}% complete", end='\r')

        # don't append target if label already ends with it
        if label.lower().endswith(target.lower()):
            sub = label
        else:
            sub = f"{label}.{target}"

        # DNS resolution
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            print_out(Fore.YELLOW + f"[SKIP:RESOLVE] {sub:30} could not resolve")
            continue

        # check Cloudflare
        try:
            is_cf = inCloudFlare(ip)
        except ValueError:
            is_cf = False

        # HTTP probe
        try:
            r = requests.get("http://"+sub, timeout=5)
            status = r.status_code
        except:
            status = "ERR"

        color = Fore.RED if is_cf else Fore.GREEN
        tag   = "CLOUDFLARE" if is_cf else "OPEN"

        print_out(
            Style.BRIGHT+Fore.WHITE+
            f"[FOUND:SUB] {sub:30} IP: {ip:15} HTTP: {status} " +
            color+tag
        )

    print_out(Fore.CYAN+"Subdomain scan complete.")

def update():
    print_out(Fore.CYAN+"Updating CF and Crimeflare data…")
    if not args.tor:
        cf = requests.get("https://www.cloudflare.com/ips-v4", timeout=10).text
        with open('data/cf-subnet.txt','w') as fd:
            fd.write(cf)
    else:
        print_out(Fore.RED+"Cannot update CF ranges over TOR")
    ipout = requests.get("https://cf.ozeliurs.com/ipout", timeout=10).text
    with open('data/ipout','w') as fd:
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
print(Fore.RED+Style.BRIGHT+logo+Fore.RESET)
print_out("Initializing CloudFail — " + datetime.datetime.now().strftime('%d/%m/%Y'))

parser = argparse.ArgumentParser()
parser.add_argument("-t","--target",   help="target URL",          type=str, required=True)
parser.add_argument("-T","--tor",      help="use TOR",   action="store_true")
parser.add_argument("-u","--update",   help="update DBs",action="store_true")
parser.add_argument("-k","--api-key",  help="DNSDumpster key",     required=True)
parser.add_argument("-s","--subdomains", metavar="FILE",
                    default="data/subdomains.txt",
                    help="path to subdomain list")
parser.add_argument("-F","--force",    action="store_true",
                    help="force scan even if wildcard DNS detected")
parser.set_defaults(tor=False, update=False)

args = parser.parse_args()

if args.tor:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,'127.0.0.1',9050)
    socket.socket = socks.socksocket
    try:
        sip = requests.get('http://ipinfo.io/ip',timeout=5).text.strip()
        print_out(Fore.WHITE+Style.BRIGHT+"TOR up, IP="+sip)
    except:
        sys.exit(1)

if args.update:
    update()

try:
    init(args.target)
    dnsdumpster(args.target)
    crimeflare(args.target)
    subdomain_scan(args.target, args.subdomains, force=args.force)
except KeyboardInterrupt:
    sys.exit(0)
