import os
import requests
from dotenv import load_dotenv

def get_api_key(service, index):
    
    key = os.getenv(f'{service.upper()}_API_{index+1}')
    
    if key is None:
        return None, None
    else:
        return index+1, key

def api_request(service, url, headers=None, data=None):

    api_key = None

    if service != 'alienvault':
        load_dotenv(f'{service}.env')
        index = 1
        api_key = os.getenv(f'{service.upper()}_API_{index}')

    while True:
        if api_key is None and service != 'alienvault':
            print(f"No API key found for {service}.")
            return None    

        if service == 'virustotal':
            headers.update({'x-apikey': api_key})
            response = requests.get(url, headers=headers)

        elif service == 'hybridanalysis':
            headers.update({'api-key': api_key})
            response = requests.post(url, headers=headers, data=data)
        
        elif service == 'malwarebazaar':
            headers.update({'API-KEY': api_key})
            response = requests.post(url, headers=headers, data=data)
        
        elif service == 'alienvault':
            response = requests.get(url)
        
        elif service == 'malshare':
            response = requests.get(url+api_key+"&action=details&hash="+data)
        
        elif service == 'metadefender':
            headers.update({'apikey': api_key})
            response = requests.get(url+data, headers=headers)

        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_api_key(service, index)
            if not api_key:
                return None

def virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {}
    return api_request("virustotal", url, headers)

def hybridanalysis(file_hash):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {'User-Agent':'Falcon'}
    data = {'hash': file_hash}
    return api_request("hybridanalysis", url, headers, data=data)

def malwarebazaar(file_hash):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {}
    data = {'query':'get_info','hash':file_hash}
    return api_request("malwarebazaar", url, headers, data)

def alienvault(file_hash):
    url = "https://otx.alienvault.com/api/v1/indicators/file/"
    return api_request("alienvault", url+file_hash+"/analysis")

def malshare(file_hash):
    url = "https://malshare.com/api.php?api_key="
    data = file_hash
    return api_request("malshare", url, None, data)

def metadefender(file_hash):
    url = "https://api.metadefender.com/v5/threat-intel/file-analysis/"
    headers = {}
    data = file_hash
    return api_request("metadefender", url, headers, data)