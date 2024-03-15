# WTSAnalyzer (WebTechSecAnalyzer)

![image](https://github.com/secnextechnologies/WTSAnalyzer/assets/102068563/79257e19-7338-42c0-ba55-182f9d568c6d)


WTSAnalyzer is a Python-based tool designed to analyze the technology stack and security aspects of a given website. It provides insights into various aspects such as technologies used, server location, SSL certificate details, DNS records, server information, HTTP security headers, and domain WHOIS information.

## Features

- **Technology Detection**: Utilizes the BuiltWith API to detect the technologies used in a website's development.
- **Server Location**: Retrieves the geographic location of the website's server.
- **SSL Certificate Details**: Fetches SSL certificate information including expiration date, issuer, etc.
- **DNS Records**: Retrieves DNS records associated with the website.
- **Server Information**: Gathers details about the website's server such as IP address, hosting provider, etc.
- **HTTP Security Headers**: Checks for the presence of security headers in the HTTP response.
- **Domain WHOIS Information**: Fetches WHOIS information for the domain.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/secnextechnologies/WTSAnalyzer.git

2. Install the required Python dependencies:
   ```bash
    pip install -r requirements.txt

3. Run the wtsanalyzer.py script:
    ```bash
    python wtsanalyzer.py

## Dependencies

   - builtwith: Python library for accessing the BuiltWith API.
   - whois: Python library for retrieving WHOIS information.
   - dns.resolver: Python library for DNS resolution.
   - ssl: Python library for SSL certificate handling.
   - socket: Python library for network communication.
   - requests: Python library for making HTTP requests.
   - colorama: Python library for colored terminal output.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
