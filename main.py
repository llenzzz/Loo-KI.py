import argparse
import sys
import file_hash

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
    
    if args.file:
        ## file input does nothing for now
        print(f"{args.file}")
        
    if args.input:
        ## just testing if magpprint, and it does.
        ## this is only specific for virustotal tho and only for hashes.
        ## TODO: later on account also for other sites.
        ## TODO: later on add logic to recognize whether url ba or ip.
        test = file_hash.virustotal(args.input)
        print(test)
    
    if args.output:
        ## file output does nothing for now
        print(f"{args.output}")


if __name__ == "__main__":
    main()
