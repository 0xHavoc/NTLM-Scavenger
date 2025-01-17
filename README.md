# NTLM-Scavenger
NTLM-Scavenger is a security testing tool designed to identify and analyze NTLM authentication endpoints that may leak internal network information. This tool is intended for authorized security testing and network auditing purposes only.

## Description
NTLM-Scavenger automates the discovery and analysis of NTLM authentication endpoints by:
- Using Shodan to identify potential NTLM-enabled endpoints
- Testing endpoints for NTLM authentication
- Decoding NTLM Type 2 messages
- Extracting internal network information from NTLM responses

The tool can extract various pieces of internal information including:
- NetBIOS Server Names
- NetBIOS Domain Names
- DNS Host Names
- DNS Domain Names
- DNS Tree Names
- NTLM Version Information
- Server Timestamps

## Prerequisites
- Python 3.7 or higher
- Shodan API key
- Required Python packages:
  - shodan
  - requests
  - requests_ntlm

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/ntlm-scavenger.git
cd ntlm-scavenger
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure your Shodan API key:
   - Replace `YOUR_SHODAN_API_KEY` in the script with your actual Shodan API key
   - Or set it as an environment variable:
     ```bash
     export SHODAN_API_KEY='your_api_key_here'
     ```

## Usage
1. Create a file named `org_list.txt` containing target organization names (one per line)

2. Run the script:
```bash
python ntlm_scavenger.py
```

3. Results will be saved in two formats:
   - JSON file for programmatic processing
   - Text file for human readability

Results are stored in a timestamped directory: `ntlm_results_YYYYMMDD_HHMMSS/`

## Output Format

### JSON Output
```json
{
    "organization_name": [
        {
            "url": "http://example.com",
            "target_name": "SERVER01",
            "server_name": "SERVER01",
            "domain_name": "CORP",
            "dns_name": "server01.corp.internal",
            "dns_domain": "corp.internal",
            "dns_tree": "corp.internal",
            "timestamp": "132892349238",
            "version": "10.0.17763"
        }
    ]
}
```

### Text Output
```
NTLM Information Scan Results - 2025-01-17 10:00:00
=====================================

Organization: Example Corp
---------------------------------
Endpoint: http://example.com
Target Name: SERVER01
Server Name: SERVER01
Domain Name: CORP
DNS Host: server01.corp.internal
DNS Domain: corp.internal
DNS Tree: corp.internal
Version: 10.0.17763
Timestamp: 132892349238
```

## Security Considerations
⚠️ **IMPORTANT**: This tool should only be used for authorized security testing.
- Only scan systems you have explicit permission to test
- Be aware that extracting internal information might be considered intrusive
- Follow responsible disclosure practices if vulnerabilities are identified
- Consider the legal implications in your jurisdiction

## Troubleshooting
Common issues:
1. Connection timeouts: Adjust the timeout value in the script
2. SSL/TLS errors: Enable/disable SSL verification as needed
3. Rate limiting: Implement delays between requests if needed

## Contributing
Feel free to fork the repository, submit issues, or create pull requests. Contributions are welcome!

## Disclaimer
This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring all testing activities comply with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.
