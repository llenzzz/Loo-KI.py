import os
import requests
from dotenv import load_dotenv
import csv
from datetime import datetime

def convert_unix_to_utc(timestamp):
    try:
        return datetime.utcfromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, TypeError):
        return "N/A"

def get_api_key(service, index):
    key = os.getenv(f'{service.upper()}_API_{index+1}')
    if key is None:
        return None, None
    else:
        return index+1, key

def api_request(service, url, headers=None, data=None):
    api_key = None
    load_dotenv(f'{service}.env')
    index = 1
    api_key = os.getenv(f'{service.upper()}_API_{index}')
    while True:
        if api_key is None:
            print(f"No API key found for {service}.")
            return None    
        if service == 'virustotal':
            headers.update({'x-apikey': api_key})
            response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            index, api_key = get_api_key(service, index)
            if not api_key:
                return None

def virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {}
    data = api_request("virustotal", url, headers)

    return {
        "MD5": data['data']['attributes']['md5'],
        "SHA-1": data['data']['attributes']['sha1'],
        "SHA-256": data['data']['attributes']['sha256'],
        "File Type": f"{data['data']['attributes']['type_description']} ({', '.join(data['data']['attributes']['type_tags'])})",
        "Magic": data['data']['attributes']['magic'],
        "TrID": ", ".join(f"{entry['probability']}% {entry['file_type']}" for entry in data['data']['attributes']['trid']),
        "File Size": f"{data['data']['attributes']['size']} bytes",
        "Creation Time": convert_unix_to_utc(data['data']['attributes'].get('creation_date', 'N/A')),
        "First Seen in the Wild": convert_unix_to_utc(data['data']['attributes'].get('first_seen_itw_date', 'N/A')),
        "First Submission": convert_unix_to_utc(data['data']['attributes'].get('first_submission_date', 'N/A')),
        "Last Submission": convert_unix_to_utc(data['data']['attributes'].get('last_submission_date', 'N/A')),
        "Last Analysis Date": convert_unix_to_utc(data['data']['attributes'].get('last_analysis_date', 'N/A')),
        "Malicious Flags": data['data']['attributes']['last_analysis_stats']['malicious'],
        "Suspicious Flags": data['data']['attributes']['last_analysis_stats']['suspicious'],
        "Undetected Flags": data['data']['attributes']['last_analysis_stats']['undetected'],
        "Harmless Flags": data['data']['attributes']['last_analysis_stats']['harmless'],
        "Timeout Flags": data['data']['attributes']['last_analysis_stats']['timeout'],
        "Confirmed Timeout Flags": data['data']['attributes']['last_analysis_stats']['confirmed-timeout'],
        "Failure Flags": data['data']['attributes']['last_analysis_stats']['failure'],
        "Type Unsupported Flags": data['data']['attributes']['last_analysis_stats']['type-unsupported'],
        "Names": ', '.join(data['data']['attributes']['names']),
        "Copyright": data['data']['attributes']['signature_info'].get('copyright', 'N/A'),
        "Product": data['data']['attributes']['signature_info'].get('product', 'N/A'),
        "Description": data['data']['attributes']['signature_info'].get('description', 'N/A'),
        "Original Name": data['data']['attributes']['signature_info'].get('original name', 'N/A'),
        "Internal Name": data['data']['attributes']['signature_info'].get('internal name', 'N/A'),
        "File Version": data['data']['attributes']['signature_info'].get('file version', 'N/A'),
        "Imports": ", ".join(item['library_name'] for item in data['data']['attributes']['pe_info'].get('import_list', [])),
        "Exports": ', '.join(data['data']['attributes']['pe_info'].get('exports', [])),
    }

input_file = "input.txt"
output_file = "output.csv"

with open(input_file, 'r') as file:
    hashes = [line.strip() for line in file if line.strip()]

with open(output_file, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.DictWriter(file, fieldnames=[
        "MD5", "SHA-1", "SHA-256", "File Type", "Magic", "TrID", "File Size",
        "Creation Time", "First Seen in the Wild", "First Submission", "Last Submission",
        "Last Analysis Date", "Malicious Flags", "Suspicious Flags", "Undetected Flags",
        "Harmless Flags", "Timeout Flags", "Confirmed Timeout Flags", "Failure Flags",
        "Type Unsupported Flags", "Names", "Copyright", "Product", "Description",
        "Original Name", "Internal Name", "File Version", "Imports", "Exports"
    ])
    writer.writeheader()
    
    for hash in hashes:
        try:
            csv_data = virustotal(hash)
            writer.writerow(csv_data)
        except Exception as e:
            print(f"[ERROR] {hash}: {e}")