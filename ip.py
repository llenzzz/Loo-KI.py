import sys
import os
import requests
from dotenv import load_dotenv


def get_api_key(service, index):
    key = os.getenv(f'{service.upper()}_API_{index+1}')
    if key is None:
        return None, None
    else:
        return index+1, key

def api_request(service, ipAddr, url, headers, data=None):
    load_dotenv(f'{service}.env')
    index = 1
    api_key = os.getenv(f'{service.upper()}_API_{index}')

    while True:
        if api_key is None:
            return None    

        if service == "geolocator":
            response = requests.get(f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ipAddr}")
        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_api_key(service, index)

def geolocator(ipAddr):
    sys.stdout.reconfigure(encoding='utf-8')
    return api_request("geolocator", ipAddr, url='', headers='')

def dnslytics(ip):
    response=requests.get(f"https://freeapi.dnslytics.net/v1/ip2asn/{ip}")
    return response.json()
