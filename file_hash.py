import requests
import api_manager

def virustotal(file_hash):
    api_key = api_manager.virustotal()
    file_hash = file_hash.strip().lower()

    if not api_key:
        raise ValueError("Error: No VirusTotal API Key")

    headers = {"x-apikey": api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()