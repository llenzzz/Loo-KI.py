import whois
import os
import requests
import hashlib
import json
from dotenv import load_dotenv
from urllib.parse import urlparse


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
            response = requests.get(url, headers=headers)
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


#TODO export_csv functionality, figure out how to do csv stuff depending on whether it is a host or url ill commennt down below this the json output pag-host and url. 
#Host output basically occurs pag walang specific url like for example the one I used below "https://voineasa.ro/contents/Tilbjeligere.dwp", this will be run as a url, however if you run it as
#voineasa.ro it will try to find all possible urls that used this host and return what url request would respond per each url available 

# URL output
# {'query_status': 'ok', 'id': '3120212', 'urlhaus_reference': 'https://urlhaus.abuse.ch/url/3120212/', 'url': 'https://voineasa.ro/contents/Tilbjeligere.dwp', 
# 'url_status': 'online', 'host': 'voineasa.ro', 'date_added': '2024-08-21 13:00:08 UTC', 'last_online': None, 'threat': 'malware_download', 
# 'blacklists': {'spamhaus_dbl': 'abused_legit_malware', 'surbl': 'not listed'}, 'reporter': 'abuse_ch', 'larted': 'true', 
# 'takedown_time_seconds': None, 'tags': ['ascii', 'Encoded', 'GuLoader'], 'payloads': [{'firstseen': '2024-08-21', 
# 'filename': None, 'file_type': 'txt', 'response_size': '478060', 'response_md5': 'cc573cae5b4a30a824d9be2fcba5e5bf', 
# 'response_sha256': '3f0c5d83533470c6184bd6511ec3d0736d3bc9cca89070c436ef919d2948f80b', 
# 'urlhaus_download': 'https://urlhaus-api.abuse.ch/v1/download/3f0c5d83533470c6184bd6511ec3d0736d3bc9cca89070c436ef919d2948f80b/', 
# 'signature': None, 'virustotal': {'result': '0 / 65', 'percent': '0.00', 
# 'link': 'https://www.virustotal.com/gui/file/3f0c5d83533470c6184bd6511ec3d0736d3bc9cca89070c436ef919d2948f80b/detection/f-3f0c5d8'}, 'imphash': None, 
# 'ssdeep': '12288:StfSSDNkvva6LPAk7xF6sxOA0mN5qd+y73007+sy7OHvzWOsJKFNW:StfpkaIp7xpRm4Uk0W4+KFNW', 'tlsh': 'T1B3A402BACA1476708F54B580ED3A349EAF003B4B1C62534EBB589D675DD4A0343EF6'}]}


# Host Output
# {'query_status': 'ok', 'urlhaus_reference': 'https://urlhaus.abuse.ch/host/voineasa.ro/', 'host': 'voineasa.ro', 'firstseen': '2024-08-21 07:27:04 UTC', 'url_count': '3', 
# 'blacklists': {'spamhaus_dbl': 'abused_legit_malware', 'surbl': 'not listed'}, 
# 'urls': [{'id': '3120468', 'urlhaus_reference': 'https://urlhaus.abuse.ch/url/3120468/', 'url': 'https://voineasa.ro/contents/NWnWu72.bin', 'url_status': 'online', 'date_added': '2024-08-21 16:00:10 UTC', 'threat': 'malware_download', 'reporter': 'abuse_ch', 'larted': 'true', 'takedown_time_seconds': None, 'tags': ['encrypted', 'GuLoader', 'rat', 'RemcosRAT']},
# {'id': '3120212', 'urlhaus_reference': 'https://urlhaus.abuse.ch/url/3120212/', 'url': 'https://voineasa.ro/contents/Tilbjeligere.dwp', 'url_status': 'online', 'date_added': '2024-08-21 13:00:08 UTC', 'threat': 'malware_download', 'reporter': 'abuse_ch', 'larted': 'true', 'takedown_time_seconds': None, 'tags': ['ascii', 'Encoded', 'GuLoader']}, 
# {'id': '3119678', 'urlhaus_reference': 'https://urlhaus.abuse.ch/url/3119678/', 'url': 'https://voineasa.ro/contents/hdnQSeddqloQmmjxBimXjTwJ75.bin', 'url_status': 'online', 'date_added': '2024-08-21 07:27:05 UTC', 'threat': 'malware_download', 'reporter': 'abuse_ch', 'larted': 'true', 'takedown_time_seconds': None, 'tags': ['rat', 'RemcosRAT']}]}



def urlHause(url):
    parsed_url = urlparse(url)
    
    if parsed_url.scheme:
        data = {'url': url}
        response = requests.post('https://urlhaus-api.abuse.ch/v1/url/', data)

    response = response.json()
    if response['query_status'] == 'ok':
        return response
