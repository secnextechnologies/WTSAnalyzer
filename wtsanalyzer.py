import builtwith
import whois
import dns.resolver
import ssl
import socket
import requests
import datetime
from colorama import Fore, Style

def detect_with_builtwith(url):
    try:
        result = builtwith.builtwith(url)
        return result
    except builtwith.BuiltWithError as e:
        print(f"{Fore.RED}Error while using builtwith: {e}{Style.RESET_ALL}")
        return None

def get_server_location(url):
    try:
        ip_address = socket.gethostbyname(url)
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        return data.get("city"), data.get("region"), data.get("country")
    except Exception as e:
        print(f"{Fore.RED}Error getting server location: {e}{Style.RESET_ALL}")
        return None, None, None

def get_ssl_certificate(url):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(f"{Fore.RED}Error getting SSL certificate: {e}{Style.RESET_ALL}")
        return None

def print_ssl_certificate_info(ssl_certificate):
    if ssl_certificate:
        print(f"{Fore.GREEN}SSL Certificate Information:{Style.RESET_ALL}")
        for key, value in ssl_certificate.items():
            if isinstance(value, tuple):
                value = ', '.join(str(item) for item in value)
            print(f"{Fore.YELLOW}{key}:{Fore.CYAN} {value}{Style.RESET_ALL}")

def get_dns_records(url):
    try:
        answers = dns.resolver.resolve(url, 'A')
        return [answer.to_text() for answer in answers]
    except Exception as e:
        print(f"{Fore.RED}Error getting DNS records: {e}{Style.RESET_ALL}")
        return None

def get_server_info(url):
    try:
        ip_address = socket.gethostbyname(url)
        response = requests.get(f"https://{url}")
        server_info = {
            "IP Address": ip_address,
            "Server": response.headers.get("Server"),
            "Hosting Provider": response.headers.get("X-Powered-By"),
            "ASN": response.headers.get("X-ASN"),
            # Add more server-related information headers if needed
        }
        return server_info
    except Exception as e:
        print(f"{Fore.RED}Error getting server information: {e}{Style.RESET_ALL}")
        return None

def check_http_security(url):
    try:
        response = requests.get(url)
        headers = response.headers

        security_headers = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-XSS-Protection": headers.get("X-XSS-Protection"),
        }

        print(f"{Fore.GREEN}HTTP Security Headers:{Style.RESET_ALL}")
        for header, value in security_headers.items():
            if value:
                print(f"{Fore.YELLOW}{header}:{Fore.GREEN} ✅ Yes{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}{header}:{Fore.RED} ❌ No{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Error checking HTTP security headers: {e}{Style.RESET_ALL}")

def print_separator():
    print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")

def print_domain_whois_info(domain_whois):
    if domain_whois:
        print(f"{Fore.GREEN}Domain WHOIS Information:{Style.RESET_ALL}")
        for key, value in domain_whois.items():
            print(f"{Fore.YELLOW}{key}:{Fore.CYAN} {value}{Style.RESET_ALL}")

def parse_whois_data(whois_data):
    parsed_data = {}
    for key, value in whois_data.items():
        if isinstance(value, list):
            parsed_data[key] = ', '.join(map(str, value))
        elif isinstance(value, datetime.datetime):
            parsed_data[key] = value.strftime('%Y-%m-%d %H:%M:%S')
        else:
            parsed_data[key] = str(value)
    return parsed_data

def get_domain_whois(url):
    try:
        domain_info = whois.whois(url)
        return parse_whois_data(domain_info)
    except Exception as e:
        print(f"{Fore.RED}Error getting domain WHOIS information: {e}{Style.RESET_ALL}")
        return None

def main():
    print(f"{Fore.CYAN}=== Website Technology and Security Detector ==={Style.RESET_ALL}")

    # Prompt the user for the domain name
    website_url = input(f"{Fore.YELLOW}Enter the domain name (e.g., example.com): {Style.RESET_ALL}")

    print_separator()
    # Detect technologies using builtwith
    builtwith_result = detect_with_builtwith(f"https://{website_url}")
    if builtwith_result:
        print(f"{Fore.GREEN}Technologies detected using builtwith:{Style.RESET_ALL}")
        for category, technologies in builtwith_result.items():
            print(f"{Fore.YELLOW}{category}:{Fore.CYAN} {', '.join(technologies)}{Style.RESET_ALL}")

    print_separator()
    # Get server location
    city, region, country = get_server_location(website_url)
    if city and region and country:
        print(f"{Fore.GREEN}Server Location:{Style.RESET_ALL} {city}, {region}, {country}")

    print_separator()
    # Get SSL certificate details
    ssl_certificate = get_ssl_certificate(website_url)
    if ssl_certificate:
        print_ssl_certificate_info(ssl_certificate)

    print_separator()
    # Get DNS records
    dns_records = get_dns_records(website_url)
    if dns_records:
        print(f"{Fore.GREEN}DNS Records:{Style.RESET_ALL}")
        for record in dns_records:
            print(f"{Fore.YELLOW}{record}{Style.RESET_ALL}")

    print_separator()
    # Get server information
    server_info = get_server_info(website_url)
    if server_info:
        print(f"{Fore.GREEN}Server Information:{Style.RESET_ALL}")
        for key, value in server_info.items():
            print(f"{Fore.YELLOW}{key}:{Fore.CYAN} {value}{Style.RESET_ALL}")

    print_separator()
    # Check HTTP security headers
    check_http_security(f"https://{website_url}")

    print_separator()
    # Get domain WHOIS information
    domain_whois = get_domain_whois(website_url)
    if domain_whois:
        print_domain_whois_info(domain_whois)

if __name__ == "__main__":
    main()
