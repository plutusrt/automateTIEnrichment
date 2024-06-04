import json
import csv
import os

import requests
import byteTI
import MISP
import RiskIQ
import VTP
import URLScan
import urllib3
#from pymisp import ExpandedPyMISP, MISPEvent

resultsFromURLScan = {}
domains = []


def getResultsFromURLScan(url, path):
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    resultsFromURLScan = response.json()
    with open(path ,'w') as resultsFromURLScanFile:
        json.dump(resultsFromURLScan, resultsFromURLScanFile, indent=4)


def parseResults(path):
    with open(path) as resultsFile:
        results = json.load(resultsFile)
        for item in results['results']:
            if  item['task']['domain'] not in domains:
                domains.append(item['task']['domain'])


def writeResults(path):
    with open(path, 'w') as outputFile:
        csvWriter = csv.writer(outputFile)
        csvWriter.writerow(['Domains'])
        for domain in domains:
            csvWriter.writerow([domain])


def checkResults(domains):
    #line = [hash, url, domain, urlscan, screenshot, ByteTI]

    results = {}
    with open(os.path.join('output', 'domains.csv'), 'r') as fp:
        with open(os.path.join('output', 'results.csv'), 'w') as fp2:
            csvReader = csv.reader(fp)
            csvWriter = csv.writer(fp2)
            csvWriter.writerow(["hash","url","domain","urlscan","screenshot","ByteTI","VT"])
            csvReader.__next__()
            for line in csvReader:
                # Checking in ByteTIP
                byteTIRep = byteTI.getURLRep(line[2])
                if byteTIRep <= 0:
                    line[5] = "Clean"
                if byteTIRep > 0:
                    line[5] = "Malicious"
                    results[line[2]] = line

                # Checking Directly in VT
                result = VTP.getURLRep(line[2])
                if result <= 0:
                    line[6] = "Clean"
                if result > 0:
                    line[6] = result
                    results[line[2]] = line

                csvWriter.writerow(line)

            #for domain in domains:
                #result = RiskIQ.checkScore(domain)
                #result = byteTI.getURLRep(domain)
            #    result = VTP.getURLRep(domain)

    print(len(results))
    print(results)
    return results

def f(url):
    result = URLScan.submitURL(url)
    try:
        hashes = URLScan.getInitialResults(result['api'])
    except KeyError as e:
        return {}
    domains = URLScan.extactDomains(hashes)

    results = checkResults(domains)
    # Parse all responses and get all links and get TI from RiskIQ
    # write code to push to MISP
    #MISP.pushToMISP(url, results)
    return results