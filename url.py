import whois
import os
import requests
import hashlib
from dotenv import load_dotenv



def get_api_key(service, index):
    key = os.getenv(f'{service.upper()}_API_{index+1}')
    if key is None:
        return None, None
    else:
        return index+1, key
    
def api_request(service, file_hash, url, headers, data=None):
    load_dotenv(f'{service}.env')
    file_hash = file_hash.strip().lower()
    
    index = 1
    api_key = os.getenv(f'{service.upper()}_API_{index}')
    
    while True:
        if api_key is None:
            return None    

        if service == "virustotal":
            headers.update({"x-apikey": api_key})
            response = requests.get(url.format(file_hash=file_hash), headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_api_key(service, index)
              
def virustotal(url_to_scan):
    hash_object = hashlib.sha256(url_to_scan.encode())
    sha256_hash = hash_object.hexdigest()
    url = f"https://www.virustotal.com/api/v3/urls/{sha256_hash}"
    headers = {
        "x-apikey": "your_api_key_here"
    }
    return api_request("virustotal", url_to_scan, url, headers)

    
def who_is(url):
    url = url.strip()
    domain = whois.whois(url)
    return domain
