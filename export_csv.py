import csv
import os
from datetime import datetime

def parse_date(timestamp):
    if isinstance(timestamp, (int, float)):
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(timestamp, str):
        try:
            timestamp = float(timestamp)
            return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return timestamp  # Utilize string if conversion fails
    elif isinstance(timestamp, list):
        return ', '.join([parse_date(ts) for ts in timestamp if ts is not None])
    elif isinstance(timestamp, datetime):
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    return str(timestamp)

def dissect_ha_data(ha_data):
    if not ha_data or len(ha_data) == 0:
        return {}

    result = ha_data[0]

    submission_date = ''
    if 'submissions' in result and len(result['submissions']) > 0:
        submission_date = result['submissions'][0].get('created_at', '')

    ha_submit_name = result['submissions'][0].get('filename', '')

    return {
        "ha_hash": result.get('sha256', ''),
        "ha_verdict": result.get('verdict', ''),
        "ha_submission_date": parse_date(submission_date),
        "ha_file_type": result.get('type', ''),
        "ha_analysis_start_time": parse_date(result.get('analysis_start_time', '')),
        "ha_submit_name": ha_submit_name
    }

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

def dissect_vt_url_data(vt_url_data):
    if not vt_url_data or 'data' not in vt_url_data:
        return {}

    attributes = vt_url_data['data']['attributes']

    return {
        "vt_url_id": vt_url_data['data']['id'],
        "vt_url_reputation": attributes.get("reputation", ''),
        "vt_url_first_submission_date": parse_date(attributes.get("first_submission_date", '')),
        "vt_url_last_analysis_date": parse_date(attributes.get("last_analysis_date", '')),
        "vt_url_last_modification_date": parse_date(attributes.get("last_modification_date", '')),
        "vt_url_total_votes_harmless": attributes.get("total_votes", {}).get("harmless", ''),
        "vt_url_total_votes_malicious": attributes.get("total_votes", {}).get("malicious", ''),
        "vt_url_scan_results": attributes.get('last_analysis_results', {}),
        "url": attributes.get("url", ''),
        "last_final_url": attributes.get("last_final_url", '')
    }

def dissect_whois_data(whois_data):
    if not whois_data:
        return {}

    return {
        "domain_name": whois_data.get('domain_name', ''),
        "registrar": whois_data.get('registrar', ''),
        "creation_date": parse_date(whois_data.get('creation_date', '')),
        "expiration_date": parse_date(whois_data.get('expiration_date', '')),
        "name_servers": ','.join(whois_data.get('name_servers', [])) if whois_data.get('name_servers') else '',
        "status": whois_data.get('status', '')
    }

def save_to_csv(data, filename):
    file_exists = os.path.exists(filename)

    headers = list(data.keys())

    with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)

        if not file_exists:
            writer.writeheader()

        try:
            writer.writerow(data)
        except Exception as e:
            print(f"Error writing to CSV: {e}")

    print(f"Data has been appended to {filename}.")

def save_hash(vt_data, ha_data, filename):
    vt_ioc = dissect_vt_data(vt_data)
    ha_ioc = dissect_ha_data(ha_data)
    merged_data = {
        "vt_hash": vt_ioc.get("vt_hash"),
        "ha_hash": ha_ioc.get("ha_hash"),
        **vt_ioc,
        **ha_ioc
    }

    if not merged_data:
        print("No data to save.")
        return

    save_to_csv(merged_data, filename)

def save_url(vt_url_data, whois_data, filename):
    vt_url_ioc = dissect_vt_url_data(vt_url_data)
    whois_ioc = dissect_whois_data(whois_data)
    merged_data = {**vt_url_ioc, **whois_ioc}

    if not merged_data:
        print("No data to save.")
        return

    save_to_csv(merged_data, filename)
