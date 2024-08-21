import os
import requests
from dotenv import load_dotenv

def get_api_key(service, index):
    key = os.getenv(f'{service.upper()}_API_{index+1}')
    if key is None:
        return None, None
    else:
        return index+1, key

def api_request(service, url, headers, data=None):
    load_dotenv(f'{service}.env')

    index = 1
    api_key = os.getenv(f'{service.upper()}_API_{index}')

    while True:
        if api_key is None:
            print(f"No API key found for {service}.")
            return None    

        if service == "virustotal":
            headers.update({"x-apikey": api_key})
            response = requests.get(url, headers=headers)
        elif service == "hybridanalysis":
            headers.update({'api-key': api_key})
            response = requests.post(url, headers=headers, data=data)
        elif service == "malwarebazaar":
            headers.update({'API-KEY': api_key})
            response = requests.post(url, headers=headers, data=data)

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