import argparse
import sys
import file_hash
import whois

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
    
    parser.add_argument (
        '-o',
        '--output',
        help = "Output Filename",
        type = str,
        ## ------------ uncomment pag okay na yung file exports pero saka na yun  ------------ ##
        # required = True
    )
    
    return parser.parse_args()

def main():

    args = parseArguments()

    if args.file and args.input:
        sys.exit(1)
    if not args.file and not args.input:
        sys.exit(1)

    ## just testing if magpprint (file and input), and they both do.
    ## this is only specific for virustotal tho and only for hashes.
    ## TODO: later on account also for other sites.
    ## TODO: later on add logic to recognize whether url ba or ip or whatever.

    if args.file:
        with open(args.file, "r") as file:
            hashList = file.readlines()
        for hash in hashList:
            print(file_hash.virustotal(hash))
        
    if args.input:
        item = file_hash.virustotal(args.input)
        print(item)
        domain= whois.whois(args.input)
        print(domain.domain_name)
        print(domain.registrar)
        print(domain.name_servers)
    
    if args.output:
        ## file output does nothing for now
        print(f"{args.output}")


if __name__ == "__main__":
    main()
