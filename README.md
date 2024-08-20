# Loo-KI.py

## Prerequisites

### Installations
```bash
pip install python-dotenv
pip install requests
pip install python-whois
```

### Components
api_manager: checks for usable api_key from specified .env file. returns usable api.
file_hash: retrieves usable api via api_manager import. returns hash lookup results.
url: retrieves usable api via api_manager import. returns URL lookup results.
main.py: checks for URL and file hashes and invokes its saving into CSV. eventually will also support ips. pass the necessary args to execute.

## Usage

### Command
sample run:
python main.py -i <hash>

-------------------------------------

utilizes gitignore to hide .env, .txt, and .csv files locally.

### Configuration
for now you SHOULD have a virustotal.env AND a hybridanalysis.env file. content format is as follows:

VIRUSTOTAL_API_1=<api_key_1a>
VIRUSTOTAL_API_2=<api_key_2a>
VIRUSTOTAL_API_3=<api_key_3a>
(and so on..)

HYBRIDANALYSIS_API_1=<api_key_1b>
HYBRIDANALYSIS_API_2=<api_key_2b>
HYBRIDANALYSIS_API_3=<api_key_3b>
(and so on..)
