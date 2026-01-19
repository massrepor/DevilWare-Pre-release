# DevilWare OSINT Tool

## Pre Release Version

One of the most comprehensive OSINT (Open Source Intelligence) tools available. DevilWare provides advanced intelligence gathering capabilities across multiple data sources and platforms.

## ✨ Features

- **🎨 Beautiful Interface**: Colorful, emoji-enhanced interface for better user experience
- **📱 Interactive Menu**: User-friendly menu system perfect for non-technical users
- **⚡ Fast Operations**: Optimized lookups with progress indicators
- **🔧 Advanced APIs**: Integration with multiple intelligence APIs
- **📊 Rich Output**: Detailed, color-coded results with visual indicators
- **🔄 Batch Processing**: Handle multiple queries from files
- **📤 JSON Export**: API-friendly structured data output

### Core OSINT Operations:

- **📞 Phone Number Intelligence**: Validation, carrier info, geolocation, and advanced API lookups
- **📧 Email Analysis**: Format validation, deliverability checks, and breach detection
- **👤 Name Investigation**: Basic parsing and social media correlation
- **🌐 IP Geolocation**: Detailed location data with organization info
- **🏠 Domain WHOIS**: Complete domain registration information
- **👥 Social Media Search**: Multi-platform presence detection
- **🔍 Username Availability**: Check across 10+ major platforms
- **🚨 Breach Detection**: Check if email was compromised in data breaches
- **📄 Pastebin Search**: Find leaked information in pastes
- **🔒 Shodan Integration**: Advanced IP/port scanning and vulnerability data
- **🖼️ Reverse Image Search**: Multiple engine correlation
- **🌑 Dark Web Education**: Safe information about dark web OSINT
- **🌐 DNS Lookup**: Comprehensive DNS record enumeration
- **🔎 Subdomain Enumeration**: Discovery scanning
- **🚪 Port Scanning**: Service detection
- **💻 MAC Address Lookup**: Hardware vendor identification
- **🚗 VIN Decoder**: Vehicle identification number analysis

## Installation

1. Install Python 3.8 or higher.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

### Windows Batch File

A convenient batch file `osint.bat` is provided for Windows users. It automatically activates the virtual environment and runs the tool.

Usage:

```
osint.bat phone "+1234567890" --api-key YOUR_KEY
```

For interactive mode (no arguments needed):

```
osint.bat
```

## Installation

1. Install Python 3.8 or higher.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

### Windows Batch File

A convenient batch file `osint.bat` is provided for Windows users. It automatically activates the virtual environment and runs the tool.

Usage:

```
osint.bat phone "+1234567890" --api-key YOUR_KEY
```

## Usage

### Interactive Mode (Recommended for Non-Coders)

Simply run the tool without arguments for a user-friendly menu:

```bash
python osint_tool.py
# or
osint.bat
```

### Command Line Mode

Run the tool with the following syntax:

```
python osint_tool.py <type> [query] [options]
```

### Options

- `--api-key KEY`: API key for services like ipinfo.io, shodan, numverify
- `--region REGION`: Default region for phone parsing (e.g., US, GB)
- `--check-deliverability`: Enable email deliverability check
- `--output-format {text,json}`: Output format (default: text)
- `--batch-file FILE`: Process multiple queries from a file (one per line)

### Examples

- **Phone Analysis**:

  ```
  python osint_tool.py phone "+16502530000" --region US --api-key YOUR_NUMVERIFY_KEY
  ```

- **Email Breach Check**:

  ```
  python osint_tool.py breach "user@example.com"
  ```

- **Username Check**:

  ```
  python osint_tool.py username "johndoe"
  ```

- **Shodan IP Scan**:

  ```
  python osint_tool.py shodan "8.8.8.8" --api-key YOUR_SHODAN_KEY
  ```

- **Reverse Image Search**:

  ```
  python osint_tool.py reverseimage "https://example.com/image.jpg"
  ```

- **Batch Processing**:
  ```
  python osint_tool.py phone --batch-file phones.txt --output-format json
  ```

### API Keys (Optional but Recommended)

- **Numverify**: Enhanced phone data - [numverify.com](https://numverify.com)
- **IPInfo**: Detailed geolocation - [ipinfo.io](https://ipinfo.io)
- **Shodan**: Port scanning & vulnerabilities - [shodan.io](https://account.shodan.io/)

### Configuration File

The tool now supports a `config.json` file for storing API keys and settings. This makes it easier to use without specifying keys on the command line every time.

**config.json structure:**

```json
{
  "api_keys": {
    "numverify": "YOUR_NUMVERIFY_KEY",
    "ipinfo": "YOUR_IPINFO_KEY",
    "shodan": "YOUR_SHODAN_KEY",
    "haveibeenpwned": "YOUR_HIBP_KEY"
  },
  "settings": {
    "default_region": "US",
    "check_deliverability": false,
    "output_format": "text",
    "timeout": 10,
    "max_results": 50
  },
  "user": {
    "name": "Your Name",
    "organization": "Your Organization",
    "notes": "Custom notes"
  },
  "advanced": {
    "enable_logging": false,
    "log_file": "devilware.log",
    "debug_mode": false,
    "custom_user_agent": "DevilWare-OSINT-Tool/1.0"
  }
}
```

The config file is automatically created with default values on first run. Simply edit the API keys in the file to enable enhanced features.

## Available Operations

1. Phone Number Lookup - Carrier, location, validation
2. Email Analysis - Format, deliverability, breaches
3. Name Investigation - Basic parsing
4. IP Geolocation - Location, organization, ports
5. Domain WHOIS - Registration details
6. Social Media Search - Multi-platform presence
7. Username Availability - Check across 10+ platforms
8. Email Breach Check - HaveIBeenPwned integration
9. Pastebin Search - Leaked data discovery
10. Shodan IP Scan - Advanced network intelligence
11. Reverse Image Search - Visual correlation
12. Dark Web Info - Educational resources
13. DNS Lookup - Record enumeration
14. Subdomain Enumeration - Discovery scanning
15. Port Scanning - Service detection
16. MAC Address Lookup - Vendor identification
17. VIN Decoder - Vehicle information

### Batch File Example

Create a file `queries.txt` with:

```
+1234567890
user@example.com
8.8.8.8
```

Then run:

```
python osint_tool.py phone --batch-file queries.txt
```

## Extending the Tool

The tool is designed to be modular. Add new lookup functions in `osint_tool.py` and update the argument parser.

For advanced OSINT:

- Integrate with paid APIs (e.g., Whitepages for phone reverse lookup, Hunter.io for email verification).
- Add web scraping with proper rate limiting and respect for terms of service.
- Use social media APIs for profile lookups.

## Legal and Ethical Considerations

- Use this tool responsibly and in accordance with applicable laws.
- Respect privacy and terms of service of data sources.
- This tool provides basic validation; advanced lookups may require paid services.

## Dependencies

- requests: For HTTP requests
- beautifulsoup4: For HTML parsing (future scraping features)
- phonenumbers: For phone number parsing
- email-validator: For email validation
- dnspython: For DNS queries (MX record checks)
- python-whois: For domain WHOIS lookups
