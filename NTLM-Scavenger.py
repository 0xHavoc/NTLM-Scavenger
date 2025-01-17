import shodan
import base64
import struct
import requests
import json
from datetime import datetime
from requests_ntlm import HttpNtlmAuth
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, asdict
import os

@dataclass
class NTLMInfo:
    url: str
    target_name: str
    server_name: str
    domain_name: str
    dns_name: str
    dns_domain: str
    dns_tree: str
    timestamp: str
    version: Optional[Tuple[int, int, int, int]] = None

    def to_dict(self):
        return {k: str(v) if isinstance(v, tuple) else v for k, v in asdict(self).items()}

class NTLMExtractor:
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
        self.session = requests.Session()
        self.results_dir = self._create_results_dir()
        
    def _create_results_dir(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_dir = f"ntlm_results_{timestamp}"
        os.makedirs(results_dir, exist_ok=True)
        return results_dir

    def save_results(self, org_results: Dict[str, List[NTLMInfo]]):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save as JSON
        json_file = os.path.join(self.results_dir, f"ntlm_results_{timestamp}.json")
        json_data = {org: [info.to_dict() for info in results] 
                    for org, results in org_results.items()}
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=4)

        # Save as readable text
        txt_file = os.path.join(self.results_dir, f"ntlm_results_{timestamp}.txt")
        with open(txt_file, 'w') as f:
            f.write(f"NTLM Information Scan Results - {datetime.now()}\n")
            f.write("="* 80 + "\n\n")
            
            for org, results in org_results.items():
                f.write(f"\nOrganization: {org}\n")
                f.write("-" * 40 + "\n")
                
                if not results:
                    f.write("No NTLM information found\n")
                    continue
                    
                for info in results:
                    f.write(f"\nEndpoint: {info.url}\n")
                    f.write(f"Target Name: {info.target_name}\n")
                    f.write(f"Server Name: {info.server_name}\n")
                    f.write(f"Domain Name: {info.domain_name}\n")
                    f.write(f"DNS Host: {info.dns_name}\n")
                    f.write(f"DNS Domain: {info.dns_domain}\n")
                    f.write(f"DNS Tree: {info.dns_tree}\n")
                    if info.version:
                        f.write(f"Version: {'.'.join(map(str, info.version))}\n")
                    f.write(f"Timestamp: {info.timestamp}\n")
                    f.write("-" * 40 + "\n")

        print(f"\nResults saved to:")
        print(f"JSON: {json_file}")
        print(f"Text: {txt_file}")

    # [Previous methods remain the same: decode_ntlm_challenge, _parse_target_info, test_endpoint]
    # Adding URL to NTLMInfo in test_endpoint method:

    def test_endpoint(self, url: str) -> Optional[NTLMInfo]:
        try:
            response = self.session.get(url, timeout=30)
            
            if 'WWW-Authenticate' in response.headers:
                auth_header = response.headers['WWW-Authenticate']
                if 'NTLM' in auth_header:
                    parts = auth_header.split()
                    ntlm_challenge = next((part for part in parts if part != 'NTLM'), None)
                    if ntlm_challenge:
                        info = self.decode_ntlm_challenge(ntlm_challenge)
                        if info:
                            # Add URL to the info object
                            info.url = url
                            return info
            return None
            
        except Exception as e:
            print(f"Error testing {url}: {e}")
            return None

    def search_organizations(self, input_file: str) -> Dict[str, List[NTLMInfo]]:
        all_results = {}
        
        with open(input_file, 'r') as f:
            orgs = [line.strip() for line in f if line.strip()]
        
        for org in orgs:
            print(f"\nSearching organization: {org}")
            org_results = []
            
            try:
                results = self.api.search(f'org:"{org}" http.status:401')
                print(f"Found {results['total']} results")
                
                for result in results['matches']:
                    url = f"http://{result['ip_str']}:{result.get('port', 80)}"
                    print(f"\nTesting: {url}")
                    
                    info = self.test_endpoint(url)
                    if info:
                        org_results.append(info)
                        print("NTLM Information Found:")
                        print(f"Target Name: {info.target_name}")
                        print(f"Server Name: {info.server_name}")
                        print(f"Domain Name: {info.domain_name}")
                        print(f"DNS Host: {info.dns_name}")
                        print(f"DNS Domain: {info.dns_domain}")
                        print(f"DNS Tree: {info.dns_tree}")
                        if info.version:
                            print(f"Version: {'.'.join(map(str, info.version))}")
                        
            except shodan.APIError as e:
                print(f"Shodan API Error: {e}")
            
            all_results[org] = org_results
            
        return all_results

def main():
    API_KEY = "YOUR_SHODAN_API_KEY"
    INPUT_FILE = "org_list.txt"
    
    extractor = NTLMExtractor(API_KEY)
    results = extractor.search_organizations(INPUT_FILE)
    extractor.save_results(results)

if __name__ == "__main__":
    main()
