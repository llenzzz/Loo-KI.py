# Loo-KI.py

```bash
pip install python-dotenv
pip install requests
pip install python-whois
```

api_manager: checks for usable api_key from specified .env file. returns usable api.
file_hash: retrieves usable api via api_manager import. returns results in json format.
main.py: checks for file hashes via file_hash. eventually will also support urls and ips. pass the necessary args to execute.

sample run:
python main.py -i <hash>

-------------------------------------

utilizes gitignore to hide .env, .txt, and .csv files locally.

for now you SHOULD have a virustotal.env AND a hybridanalysis.env file. content format is as follows:

VIRUSTOTAL_API_1=<api_key_1a>
VIRUSTOTAL_API_2=<api_key_2a>
VIRUSTOTAL_API_3=<api_key_3a>
(and so on..)

HYBRIDANALYSIS_API_1=<api_key_1b>
HYBRIDANALYSIS_API_2=<api_key_2b>
HYBRIDANALYSIS_API_3=<api_key_3b>
(and so on..)