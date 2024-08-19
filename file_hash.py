import os
import requests
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
        elif service == "hybridanalysis":
            headers.update({'api-key': api_key})
            response = requests.post(url, headers=headers, data=data)
        
        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_api_key(service, index)

def virustotal(file_hash):
    url = "https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {}
    return api_request("virustotal", file_hash, url, headers)

def hybridanalysis(file_hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {'User-Agent': 'Falcon'}
    data = {'hash': file_hash}
    return api_request("hybridanalysis", file_hash, url, headers, data=data)
