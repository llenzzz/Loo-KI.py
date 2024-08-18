import os
import requests
import csv
import time
import argparse
import datetime
from typing import List, Dict

sAPIKeyFile = 'KipyKeys.txt'

class Kipy:
    def __init__(self):
        self.sAPIKeys = {}
        self.sCompiledOutputs = []
        self.loadAPIKeys()

    def loadAPIKeys(self):
        # Loading API Keys from a text file
        if os.path.exists(sAPIKeyFile):
            with open(sAPIKeyFile, 'r') as KeyFile:
                for line in KeyFile:
                    if '=' in line:
                        sSource, sKey = line.strip().split('=', 1)
                        self.sAPIKeys[sSource] = sKey
                        print(f"Loaded API key for {sSource}: {sKey}")

    def storeAPIKeys(self):
        # Storing API Keys into a text file, for future reference
        with open(sAPIKeyFile, 'w') as KeyFile:
            for sSource, sKey in self.sAPIKeys.items():
                KeyFile.write(f"{sSource}={sKey}\n")
        print(f"API key saved to {sAPIKeyFile}")

    def setAPIKey(self, sSource: str):
        # Warrants an API key for a particular source (i.e. VirusTotal)
        sKey = input(f"API key for {sSource}: ").strip()
        if sKey:
            self.sAPIKeys[sSource] = sKey
            self.storeAPIKeys()  # Save new key to KipyKeys.txt
            print(f"Stored API key for {sSource}")
        else:
            print(f"API key for {sSource} is invalid or empty.")
            self.setAPIKey(sSource)

    def getAPIKey(self, sSource: str) -> str:
        # Gets API key for a particular source (i.e. VirusTotal)
        if sSource not in self.sAPIKeys:
            self.setAPIKey(sSource)
        return self.sAPIKeys.get(sSource)

    def normalizeHash(self, sHash: str) -> str:
        # Normalization of hash inputs with lowercasing
        return sHash.strip().lower()

    def lookupVirusTotal(self, sHash: str) -> Dict:
        # Lookup with VirusTotal API
        sKey = self.getAPIKey("virustotal")
        if not sKey:
            raise ValueError("Error: No VirusTotal API Key")

        headers = {"x-apikey": sKey}
        sURL = f"https://www.virustotal.com/api/v3/files/{sHash}"
        
        print(f"Requesting URL <{sURL}> with headers: <{headers}>")

        sResponse = requests.get(sURL, headers=headers)
        
        print(f"Response Status Code: {sResponse.status_code}")
        print(f"Response Text: {sResponse.text}")

        if sResponse.status_code == 200:
            return sResponse.json()
        else:
            return {"Error": f"Request failed, status: {sResponse.status_code}: {sResponse.text}"}

    def executeLookup(self, sHash: str) -> Dict:
        # Function calls for each API lookup goes here, I thinkk
        sNormalized = self.normalizeHash(sHash)
        sOutput = {"hash": sNormalized}
        sVirusTotalOuts = self.lookupVirusTotal(sNormalized)
        
        sOutput.update({"virustotal": sVirusTotalOuts})
        self.sCompiledOutputs.append(sOutput)
        return sOutput

    def makeCSV(self, filename: str):
        # CSV Output
        if self.sCompiledOutputs:
            sKeys = set().union(*(d.keys() for d in self.sCompiledOutputs))
            with open(filename, "w", newline="", encoding="utf-8") as CSVFIle:
                dict_writer = csv.DictWriter(CSVFIle, fieldnames=sKeys)
                dict_writer.writeheader()
                dict_writer.writerows(self.sCompiledOutputs)

    def displayOutput(self):
        # Print outputs
        for i in self.sCompiledOutputs:
            print(i)

def parseArguments():
    parser = argparse.ArgumentParser(description="IOC Lookup Tool")
    parser.add_argument("-f", "--file", help="File containing list of inputs", type=str)
    parser.add_argument("-u", "--input", help="Single input", type=str)
    parser.add_argument("-o", "--output", help="Output CSV file name", type=str, default="results.csv")
    parser.add_argument("-d", "--defanged", help="Defanged URL", action='store_true')
    return parser.parse_args()

def main():
    args = parseArguments()
    Tool = Kipy()

    if args.file:
        with open(args.file, "r") as file:
            hashes = file.readlines()
        for sHash in hashes:
            Tool.executeLookup(sHash.strip())
    elif args.input:
        Tool.executeLookup(args.input)
    else:
        print("Parameters are file (-f) or single (-u) input.")
        return

    Tool.makeCSV(args.output)
    Tool.displayOutput()

if __name__ == "__main__":
    main()
