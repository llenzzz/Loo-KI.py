import argparse
import sys
import re
import file_hash
import url
import export_csv
import ip
REG_HASH = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
REG_URL = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$'
REG_IP = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

def parseArguments():
    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        '-f',
        '--file',
        help="Input Filename",
        type=str
    )
    
    parser.add_argument(
        '-i',
        '--input',
        help="String Input",
        type=str
    )
    
    return parser.parse_args()

def process_hash(item):
    vt_data = file_hash.virustotal(item)
    ha_data = file_hash.hybridanalysis(item)
    if vt_data or ha_data:
        export_csv.save_hash(vt_data, ha_data, f"Hash_Lookups.csv")

def process_url(item):
    vt_data = url.virustotal(item)
    whois_data = url.who_is(item)
    if whois_data or vt_data:
        export_csv.save_url(vt_data, whois_data, f"URL_Lookups.csv")

def main():
    args = parseArguments()

    if args.file and args.input:
        sys.exit("Error: You can either provide a file or a string input, not both.")
    if not args.file and not args.input:
        sys.exit("Error: No input provided. Please provide a file or string input.")

    regex_hash = re.compile(REG_HASH)
    regex_url = re.compile(REG_URL)

    if args.file:
        with open(args.file, "r") as file:
            itemList = file.readlines()

        for item in itemList:
            item = item.strip()
            if regex_hash.match(item):
                process_hash(item)
            elif regex_url.match(item):
                process_url(item)

    elif args.input:
        input_data = args.input.strip()
        regex = re.compile(REG_HASH)
        if regex.match(input_data):
            print("Hash")
            process_hash(input_data)
            print(file_hash.virustotal(input_data))
            print(file_hash.hybridanalysis(input_data))

        regex = re.compile(REG_URL)
        if regex.match(input_data):
            print("URL")
            process_url(input_data)
            print(url.virustotal(input_data))
            print(url.who_is(input_data))
        
        regex = re.compile(REG_IP)
        if regex.match(input_data):
            print("IP address")
            print( ip.virustotal(input_data))
            print( url.who_is(input_data))
            print(ip.geolocator(input_data))
            print(ip.dnslytics(input_data))

if __name__ == "__main__":
    main()
