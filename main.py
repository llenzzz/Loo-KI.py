import argparse
import sys
import re

import file_hash
import url

REG_HASH = r'[a-fA-F0-9]'
REG_URL = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$'
REG_IP = r''

def parseArguments():

    parser = argparse.ArgumentParser()
    
    parser.add_argument (
        '-f',
        '--file',
        help = "Input Filename", 
        type = str
    )
    
    parser.add_argument (
        '-i',
        '--input',
        help = "String Input",
        type = str
    )
    
    # parser.add_argument (
    #     '-o',
    #     '--output',
    #     help = "Output Filename",
    #     type = str,
    #     required = True
    # )
    
    return parser.parse_args()

def main():

    args = parseArguments()

    if args.file and args.input:
        sys.exit(1)
    if not args.file and not args.input:
        sys.exit(1)

    if args.file:

        with open(args.file, "r") as file:
            itemList = file.readlines()
        
        regex = re.compile(REG_HASH)
        if regex.match(itemList[0]):
            for item in itemList:
                print(file_hash.virustotal(item))
                print(file_hash.hybridanalysis(item))

        regex = re.compile(REG_URL)
        if regex.match(itemList[0]):
            for item in itemList:
                print(url.who_is(item))

    if args.input:

        regex = re.compile(REG_HASH)
        if regex.match(args.input):
            print(file_hash.virustotal(args.input))
            print(file_hash.hybridanalysis(args.input))
        
        regex = re.compile(REG_URL)
        if regex.match(args.input):
            print(url.virustotal(args.input))
            print(url.who_is(args.input))
    
    # if args.output:
    #     print(f"{args.output}")

if __name__ == "__main__":
    main()
