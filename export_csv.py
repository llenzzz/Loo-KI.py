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

def dissect_alienvault_data(av_data):
    if not av_data or 'analysis' not in av_data:
        return {}

    analysis = av_data['analysis']['info']['results']
    virustotal = av_data['analysis']['plugins'].get('cuckoo', {}).get('result', {}).get('virustotal', {})
    
    return {
        "av_hash": analysis.get('sha256', ''),
        "av_file_type": analysis.get('file_type', ''),
        "av_last_analysis_date": parse_date(virustotal.get('scan_date', '')),
        "av_total_positives": virustotal.get('positives', 0),
        "av_total_scans": virustotal.get('total', 0)
    }

def dissect_malshare_data(ms_data):
    if not ms_data or 'SHA256' not in ms_data:
        return {}

    return {
        "ms_hash": ms_data.get('SHA256', ''),
        "ms_file_type": ms_data.get('F_TYPE', ''),
        "ms_filenames": ', '.join(ms_data.get('FILENAMES', []))
    }

def dissect_metadefender_data(md_data):
    if not md_data or 'sha256' not in md_data:
        return {}

    file_info = md_data.get('file_info', {})

    return {
        "md_hash": md_data.get('sha256', ''),
        "md_file_type": file_info.get('file_type', ''),
        "md_file_size": file_info.get('file_size', ''),
        "md_first_seen": parse_date(md_data.get('first_seen', '')),
        "md_last_analysis_date": parse_date(md_data.get('last_seen', '')),
        "md_malware_families": ', '.join(md_data.get('last_av_scan', {}).get('malware_families', [])),
    }

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
        "mb_first_submission_date": parse_date(result.get('first_seen', ''))
    }
    
def dissect_vt_data(vt_data):
    if not vt_data or 'data' not in vt_data:
        return {}

    attributes = vt_data['data']['attributes']

    return {
        "vt_hash": vt_data['data']['id'],
        "vt_first_submission_date": parse_date(attributes.get("first_submission_date")),
        "vt_last_analysis_date": parse_date(attributes.get("last_analysis_date")),
        "vt_last_modification_date": parse_date(attributes.get("last_modification_date")),
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
        "vt_last_final_url": attributes.get("last_final_url", '')
    }
    
def dissect_url_huas_data(url_huas_data):
    if not url_huas_data:
        return {}
    return {
        'uh_url':url_huas_data.get('url',''),
        'uh_status':url_huas_data.get('status',''),
        'uh_host':url_huas_data.get('host',''),
        'uh_date_added':url_huas_data.get('date_added',''),
        'uh_threat':url_huas_data.get('threat',''),
        'uh_blacklists':url_huas_data.get('blacklists',''),
        'uh_filenames':url_huas_data.get('filenames',''),
        'uh_file_names':url_huas_data.get('file_names',''),
        'uh_signature':url_huas_data.get('signature',''),
    }


def dissect_whois_data(whois_data):
    if not whois_data:
        return {}

    return {
        "whois_domain_name": whois_data.get('domain_name', ''),
        "whois_registrar": whois_data.get('registrar', ''),
        "whois_creation_date": parse_date(whois_data.get('creation_date', '')),
        "whois_expiration_date": parse_date(whois_data.get('expiration_date', '')),
        "whois_name_servers": ','.join(whois_data.get('name_servers', [])) if whois_data.get('name_servers') else '',
        "whois_status": whois_data.get('status', '')
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

def save_hash(vt_data, ha_data, mb_data, av_data, ms_data, md_data, filename):
    vt_ioc = dissect_vt_data(vt_data)
    ha_ioc = dissect_ha_data(ha_data)
    mb_ioc = dissect_mb_data(mb_data)
    av_ioc = dissect_alienvault_data(av_data)
    ms_ioc = dissect_malshare_data(ms_data)
    md_ioc = dissect_metadefender_data(md_data)
    
    merged_data = {
        **vt_ioc,
        **ha_ioc,
        **mb_ioc,
        **av_ioc,
        **ms_ioc,
        **md_ioc
    }
    
    ordering = [
        # Hash values
        "vt_hash", "ha_hash", "mb_hash", "av_hash", "ms_hash", "md_hash",
        
        # File metadata
        "ha_submit_name", "mb_file_name", "ms_filenames", "md_file_type", "av_file_type", "ms_file_type",

        # Malware information
        "mb_file_type", "md_malware_families", "av_total_positives", "av_total_scans",
        
        # Submission and analysis dates
        "vt_first_submission_date", "ha_submission_date", "mb_first_submission_date", "md_first_seen",
        "vt_last_analysis_date", "ha_analysis_start_time", "md_last_analysis_date", "av_last_analysis_date"
    ]
    
    ordered_data = {key: merged_data.get(key, '') for key in ordering}

    if not any(ordered_data.values()):
        print("No data to save.")
        return

    save_to_csv(ordered_data, filename)

def save_url(vt_url_data, whois_data,uh_url_data, filename):
    vt_url_ioc = dissect_vt_url_data(vt_url_data)
    whois_ioc = dissect_whois_data(whois_data)
    uh_ioc=dissect_url_huas_data(uh_url_data)
    merged_data = {**vt_url_ioc, **whois_ioc,**uh_ioc}

    ordering = [
        "vt_url_id", "vt_last_final_url",
        "vt_url_reputation", "vt_url_first_submission_date", "vt_url_last_analysis_date", "vt_url_last_modification_date",
        "vt_url_total_votes_harmless", "vt_url_total_votes_malicious", "vt_url_scan_results",
        "whois_domain_name", "whois_registrar", "whois_creation_date", "whois_expiration_date", "whois_name_servers", "whois_status","uh_url","uh_status","uh_host",
        "uh_date_added","uh_threat","uh_blacklists","uh_filenames","uh_file_names","uh_signature"
    ]
    
    ordered_data = {key: merged_data.get(key) for key in ordering if key in merged_data}

    if not ordered_data:
        print("No data to save.")
        return

    save_to_csv(ordered_data, filename)

def save_ip(geo_data, vt_ip_data, dnslytics_data, filename):
    geo_ioc = dissect_geolocator_data(geo_data)
    vt_ip_ioc = dissect_virustotal_ip_data(vt_ip_data)
    dnslytics_ioc = dissect_dnslytics_data(dnslytics_data)

    merged_data = {**geo_ioc, **vt_ip_ioc, **dnslytics_ioc}

    ordering = [
        "geo_ip", "vt_ip_address", "dns_ip",
        "geo_country_name", "vt_country", "geo_region_name", "geo_city", "geo_timezone",
        "geo_isp", "geo_organization", "geo_as", "dns_asn",
        "vt_reputation", "vt_malicious_votes", "vt_harmless_votes", "vt_last_analysis_stats", "vt_last_analysis_date"
    ]
    
    ordered_data = {key: merged_data.get(key) for key in ordering if key in merged_data}

    if not ordered_data:
        print("No data to save.")
        return

    save_to_csv(ordered_data, filename)
