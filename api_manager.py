import os
from dotenv import load_dotenv
import itertools
import requests

SAMPLE_HASH = '20aab43372669e0c8d5b01fc2a221a0d04bfa6862eadc5c3aeeae8a46eef2f22'

def virustotal():
    load_dotenv('virustotal.env')
    
    api_keys = []
    index = 1

    while True:
        key = os.getenv(f'VIRUSTOTAL_API_{index}')
        if key is None:
            break
        api_keys.append(key)
        index += 1

    for api_key in itertools.cycle(api_keys):
        headers = {'x-apikey': api_key}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/files/{SAMPLE_HASH}", headers=headers)
            if response.status_code == 200:
                return api_key
        except requests.RequestException as e:
           print(e) 

    return None
