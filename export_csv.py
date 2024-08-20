import csv
import os
from datetime import datetime

def parse_date(timestamp):
    if isinstance(timestamp, int):
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(timestamp, str):
        try:
            return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return timestamp
    elif isinstance(timestamp, list):  # Handle list of timestamps
        return ', '.join([parse_date(ts.timestamp() if isinstance(ts, datetime) else ts) for ts in timestamp if ts is not None])
    elif isinstance(timestamp, datetime):
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    elif timestamp is None:
        return ''
    return str(timestamp)

def dissect_vt_data(vt_data):
    if not vt_data or 'data' not in vt_data:
        return {}

    attributes = vt_data['data']['attributes']
    return {
        "vt_hash": vt_data['data']['id'],
        "vt_reputation": attributes.get("reputation"),
        "vt_first_submission_date": parse_date(attributes.get("first_submission_date")),
        "vt_last_analysis_date": parse_date(attributes.get("last_analysis_date")),
        "vt_last_modification_date": parse_date(attributes.get("last_modification_date")),
        "vt_total_votes_harmless": attributes.get("total_votes", {}).get("harmless"),
        "vt_total_votes_malicious": attributes.get("total_votes", {}).get("malicious"),
        "vt_antiy_result": attributes.get('last_analysis_results', {}).get('Antiy-AVL', {}).get('result'),
        "vt_antiy_category": attributes.get('last_analysis_results', {}).get('Antiy-AVL', {}).get('category')
    }

def dissect_ha_data(ha_data):
    if not ha_data or len(ha_data) == 0:
        return {}

    result = ha_data[0]
    return {
        "ha_hash": result.get('sha256', ''),
        "ha_verdict": result.get('verdict', ''),
        "ha_environment_id": result.get('environment_id', ''),
        "ha_submit_name": result.get('submit_name', ''),
        "ha_submission_date": parse_date(result.get('submit_date', '')),
        "ha_analysis_start_time": parse_date(result.get('analysis_start_time', '')),
        "ha_file_type": result.get('type', ''),
        "ha_classification_tags": ','.join(result.get('classification_tags', []))
    }

def dissect_whois_data(whois_data):
    if not whois_data:
        return {}

    return {
        "domain_name": whois_data.domain_name,
        "registrar": whois_data.registrar,
        "creation_date": parse_date(whois_data.creation_date),
        "expiration_date": parse_date(whois_data.expiration_date),
        "name_servers": ','.join(whois_data.name_servers) if whois_data.name_servers else None,
        "status": whois_data.status
    }

def load_existing_data(filename):
    if not os.path.exists(filename):
        return {}

    existing_data = {}
    with open(filename, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            unique_key = row.get('vt_hash') or row.get('ha_hash') or row.get('domain_name')  # Use the appropriate key
            if unique_key:
                existing_data[unique_key] = row
    return existing_data

def save_to_csv(data, filename):
    existing_data = load_existing_data(filename)
    unique_key = data.get('vt_hash') or data.get('ha_hash') or data.get('domain_name')

    if unique_key:
        existing_data[unique_key] = data

    headers = sorted(existing_data[next(iter(existing_data))].keys()) if existing_data else sorted(data.keys())
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for row in existing_data.values():
            writer.writerow(row)
    
    print(f"Data has been written to {filename}.")

def save_hash(vt_data, ha_data, filename):
    vt_ioc = dissect_vt_data(vt_data)
    ha_ioc = dissect_ha_data(ha_data)
    merged_data = {**vt_ioc, **ha_ioc}
    save_to_csv(merged_data, filename)

def save_url(whois_data, filename):
    dissected_data = dissect_whois_data(whois_data)
    save_to_csv(dissected_data, filename)
