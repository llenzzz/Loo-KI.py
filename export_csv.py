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

# Hash Lookup Functions:

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

def dissect_mb_data(mb_data):
    if not mb_data or 'data' not in mb_data:
        return {}

    result = mb_data['data'][0]

    return {
        "mb_hash": result.get('sha256_hash', ''),
        "mb_file_name": result.get('file_name', ''),
        "mb_file_type": result.get('file_type', ''),
        "mb_first_submission_date": parse_date(result.get('first_seen', '')),
        "mb_tags": ', '.join(result.get('tags', []))
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
    
# URL Lookup Functions:    
    
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

# IP Lookup Functions:

def dissect_geolocator_data(geo_data):
    if not geo_data:
        return {}

    return {
        "geo_ip": geo_data.get('ip', ''),
        "geo_country_name": geo_data.get('country_name', ''),
        "geo_region_name": geo_data.get('state_prov', ''),
        "geo_city": geo_data.get('city', ''),
        "geo_isp": geo_data.get('isp', ''),
        "geo_organization": geo_data.get('organization', ''),
        "geo_as": geo_data.get('asn', ''),
        "geo_timezone": geo_data.get('time_zone', {}).get('name', '')
    }

def dissect_virustotal_ip_data(vt_ip_data):
    if not vt_ip_data or 'data' not in vt_ip_data:
        return {}

    attributes = vt_ip_data['data']['attributes']

    return {
        "vt_ip_address": vt_ip_data['data'].get('id', ''),
        "vt_country": attributes.get('country', ''),
        "vt_reputation": attributes.get('reputation', ''),
        "vt_malicious_votes": attributes.get('total_votes', {}).get('malicious', 0),
        "vt_harmless_votes": attributes.get('total_votes', {}).get('harmless', 0),
        "vt_last_analysis_stats": attributes.get('last_analysis_stats', {}),
        "vt_last_analysis_date": parse_date(attributes.get('last_analysis_date'))
    }

def dissect_dnslytics_data(dnslytics_data):
    if not dnslytics_data:
        return {}

    return {
        "dns_ip": dnslytics_data.get('ip', ''),
        "dns_asn": dnslytics_data.get('asn', '')
    }

# CSV Functions:

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

def save_hash(vt_data, ha_data, mb_data, filename):
    vt_ioc = dissect_vt_data(vt_data)
    ha_ioc = dissect_ha_data(ha_data)
    mb_ioc = dissect_mb_data(mb_data)
    
    merged_data = {
        "vt_hash": vt_ioc.get("vt_hash"),
        "ha_hash": ha_ioc.get("ha_hash"),
        "mb_hash": mb_ioc.get("mb_hash"),
        **vt_ioc,
        **ha_ioc,
        **mb_ioc
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
    
def save_ip(geo_data, vt_ip_data, dnslytics_data, filename):
    geo_ioc = dissect_geolocator_data(geo_data)
    vt_ip_ioc = dissect_virustotal_ip_data(vt_ip_data)
    dnslytics_ioc = dissect_dnslytics_data(dnslytics_data)
    
    merged_data = {**geo_ioc, **vt_ip_ioc, **dnslytics_ioc}

    if not merged_data:
        print("No data to save.")
        return

    save_to_csv(merged_data, filename)
