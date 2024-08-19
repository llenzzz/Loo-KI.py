import os
import requests
from dotenv import load_dotenv

def get_virustotal_api_key(index):
    key = os.getenv(f'VIRUSTOTAL_API_{index+1}')
    if key is None:
        return None, None
    else:
        return index+1, key

def virustotal(file_hash):
    load_dotenv('virustotal.env')
    file_hash = file_hash.strip().lower()
    
    index = 1
    while True:

        if index is None:
            return None
        
        api_key = os.getenv(f'VIRUSTOTAL_API_{index}')       
        headers = {"x-apikey": api_key}
        
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_virustotal_api_key(index)