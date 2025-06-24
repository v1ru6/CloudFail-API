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
import zipfile
import os
import win_inet_pton
import platform
from colorama import Fore, Style
from DNSDumpsterAPI import DNSDumpsterAPI
import dns.resolver
import collections
collections.Callable = collections.abc.Callable

colorama.init(Style.BRIGHT)

def print_out(data, end='\n'):
    datetimestr = datetime.datetime.now().strftime('%H:%M:%S')
    print(Style.NORMAL + "[" + datetimestr + "] " + re.sub(' +', ' ', data) + Style.RESET_ALL, end=end)

def ip_in_subnetwork(ip_address, subnetwork):
    ip_integer, version1 = ip_to_integer(ip_address)
    ip_lower, ip_upper, version2 = subnetwork_to_ip_range(subnetwork)
    if version1 != version2:
        raise ValueError("incompatible IP versions")
    return ip_lower <= ip_integer <= ip_upper

def ip_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            if platform.system().startswith('Windows'):
                ip_bin = win_inet_pton.inet_pton(version, ip_address)
            else:
                ip_bin = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_bin), 16)
            return ip_integer, 4 if version == socket.AF_INET else 6
        except:
            pass
    raise ValueError("invalid IP address")

def subnetwork_to_ip_range(subnetwork):
    try:
        network_prefix, netmask_len = subnetwork.split('/')
        netmask_len = int(netmask_len)
        for version in (socket.AF_INET, socket.AF_INET6):
            ip_len = 32 if version == socket.AF_INET else 128
            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) ^ suffix_mask
                ip_bin = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_bin), 16) & netmask
                ip_upper = ip_lower + suffix_mask
                return ip_lower, ip_upper, 4 if version == socket.AF_INET else 6
            except:
                pass
    except:
        pass
    raise ValueError("invalid subnetwork")

def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing for misconfigured DNS using DNSDumpster API…")
    api = DNSDumpsterAPI(api_key=args.api_key, verbose=False)
    try:
        res = api.search(target, page=None, include_map=False)
    except Exception as e:
        print_out(Fore.RED + f"DNSDumpster API error: {e}")
        return

    for entry in res.get('a', []):
        host = entry.get('host')
        for ipinfo in entry.get('ips', []):
            ip       = ipinfo.get('ip')
            asn      = ipinfo.get('asn')
            provider = ipinfo.get('asn_name')
            country  = ipinfo.get('country')
            print_out(Style.BRIGHT + Fore.WHITE +
                      f"[FOUND:A]      {host} → {ip}   {asn}   {provider}   {country}")

    for entry in res.get('ns', []):
        host = entry.get('host')
        for ipinfo in entry.get('ips', []):
            ip       = ipinfo.get('ip')
            asn      = ipinfo.get('asn')
            provider = ipinfo.get('asn_name')
            country  = ipinfo.get('country')
            print_out(Style.BRIGHT + Fore.WHITE +
                      f"[FOUND:NS]     {host} → {ip}   {asn}   {provider}   {country}")

    for entry in res.get('mx', []):
        host = entry.get('host')
        for ipinfo in entry.get('ips', []):
            ip       = ipinfo.get('ip')
            asn      = ipinfo.get('asn')
            provider = ipinfo.get('asn_name')
            country  = ipinfo.get('country')
            print_out(Style.BRIGHT + Fore.WHITE +
                      f"[FOUND:MX]     {host} → {ip}   {asn}   {provider}   {country}")

    for entry in res.get('cname', []):
        host = entry.get('host')
        for ipinfo in entry.get('ips', []):
            ip       = ipinfo.get('ip')
            asn      = ipinfo.get('asn')
            provider = ipinfo.get('asn_name')
            country  = ipinfo.get('country')
            print_out(Style.BRIGHT + Fore.WHITE +
                      f"[FOUND:CNAME]  {host} → {ip}   {asn}   {provider}   {country}")

    for txt in res.get('txt', []):
        print_out(Style.BRIGHT + Fore.WHITE +
                  f"[FOUND:TXT]    {txt}")

def crimeflare(target):
    print_out(Fore.CYAN + "Scanning Crimeflare database...")
    crimeFound = []
    with open("data/ipout", "r") as ins:
        for line in ins:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == target:
                crimeFound.append(parts[2])
    if crimeFound:
        for ip in crimeFound:
            print_out(Style.BRIGHT + Fore.WHITE + "[FOUND:IP] " + Fore.GREEN + ip.strip())
    else:
        print_out("Did not find anything.")

def init(target):
    if not target:
        print_out(Fore.RED + "No target set, exiting")
        sys.exit(1)
    print_out(Fore.CYAN + "Fetching initial information from: " + target + "...")
    if not os.path.isfile("data/ipout"):
        print_out(Fore.CYAN + "No ipout file found, fetching data")
        update()
        print_out(Fore.CYAN + "ipout file created")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_out(Fore.RED + "Domain is not valid, exiting")
        sys.exit(0)
    print_out(Fore.CYAN + "Server IP: " + ip)
    print_out(Fore.CYAN + "Testing if " + target + " is on the Cloudflare network...")
    try:
        if inCloudFlare(ip):
            print_out(Style.BRIGHT + Fore.GREEN + target + " is part of the Cloudflare network!")
        else:
            print_out(Fore.RED + target + " is not part of the Cloudflare network, quitting...")
            sys.exit(0)
    except ValueError:
        print_out(Fore.RED + "IP address does not appear to be within Cloudflare range, shutting down..")
        sys.exit(0)

def inCloudFlare(ip):
    with open(os.path.join(os.getcwd(), 'data/cf-subnet.txt')) as f:
        for line in f:
            if ip_in_subnetwork(ip, line.strip()):
                return True
    return False

def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    try:
        resolver.resolve('*.' + target)
        choice = ''
        while choice not in ('y','n'):
            choice = input("Wildcard DNS entry found—scan subdomains anyway? (y/n): ").lower()
        return choice == 'n'
    except:
        return False

def subdomain_scan(target, subdomains_path):
    i = 0
    if check_for_wildcard(target):
        print_out(Fore.CYAN + "Wildcard detected—aborting subdomain scan.")
        return
    try:
        with open(subdomains_path, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        total = len(lines)
        print_out(Fore.CYAN + f"Scanning {total} subdomains from {subdomains_path}, please wait...")
        for idx, word in enumerate(lines, start=1):
            if total and idx % max(1, total // 100) == 0:
                pct = round((idx / total) * 100.0, 2)
                print_out(Fore.CYAN + f"{pct}% complete", '\r')
            sub = f"{word}.{target}"
            try:
                resp = requests.get("http://" + sub, timeout=5)
                status = resp.status_code
                ip = socket.gethostbyname(sub)
                if not inCloudFlare(ip):
                    i += 1
                    print_out(Style.BRIGHT + Fore.WHITE +
                              f"[FOUND:SUBDOMAIN] {sub} IP: {ip} HTTP: {status}")
                else:
                    print_out(Style.BRIGHT + Fore.WHITE +
                              f"[FOUND:SUBDOMAIN] {sub} ON CLOUDFLARE NETWORK!")
            except:
                pass
        if i == 0:
            print_out(Fore.CYAN + "Scanning finished—no new subdomains found.")
        else:
            print_out(Fore.CYAN + "Scanning finished.")
    except IOError:
        print_out(Fore.RED + "Subdomains file does not exist, aborting scan...")
        sys.exit(1)

def update():
    print_out(Fore.CYAN + "Checking for updates…")
    # update Cloudflare IP ranges
    if not args.tor:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get("https://www.cloudflare.com/ips-v4", headers=headers, stream=True)
        with open('data/cf-subnet.txt', 'wb') as fd:
            for chunk in r.iter_content(4096):
                fd.write(chunk)
    else:
        print_out(Fore.RED + "Unable to fetch Cloudflare subnet while TOR is active")
    # update Crimeflare database
    print_out(Fore.CYAN + "Updating Crimeflare database…")
    r = requests.get("https://cf.ozeliurs.com/ipout", stream=True)
    with open('data/ipout', 'wb') as fd:
        for chunk in r.iter_content(4096):
            fd.write(chunk)

# ---- MAIN ----

logo = r"""
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.5                      by m0rtem
"""
print(Fore.RED + Style.BRIGHT + logo + Fore.RESET)
print_out("Initializing CloudFail - the date is: " + datetime.datetime.now().strftime('%d/%m/%Y'))

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target URL of the website", type=str, required=True)
parser.add_argument("-T", "--tor", action="store_true", help="enable TOR routing")
parser.add_argument("-u", "--update", action="store_true", help="update databases")
parser.add_argument("-k", "--api-key", help="DNSDumpster API key", type=str, required=True)
parser.add_argument("-s", "--subdomains",
                    metavar="FILE",
                    default="data/subdomains.txt",
                    help="path to subdomains wordlist (default: data/subdomains.txt)")
parser.set_defaults(tor=False, update=False)

args = parser.parse_args()

if args.tor:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
    socket.socket = socks.socksocket
    try:
        tor_ip = requests.get('http://ipinfo.io/ip').text.strip()
        print_out(Fore.WHITE + Style.BRIGHT + "TOR connection established!")
        print_out(Fore.WHITE + Style.BRIGHT + "New IP: " + tor_ip)
    except:
        sys.exit(0)

if args.update:
    update()

try:
    init(args.target)
    dnsdumpster(args.target)
    crimeflare(args.target)
    subdomain_scan(args.target, args.subdomains)
except KeyboardInterrupt:
    sys.exit(0)
