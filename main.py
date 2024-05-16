import json
import csv
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
    results = {}
    for domain in domains:
        #result = RiskIQ.checkScore(domain)
        result = byteTI.getURLRep(domain)
        #result = VTP.getURLRep(domain)
        if result > 0:
            results[domain] = result
    print(len(results))
    print(results)
    return results

def f(url):
    result = URLScan.submitURL(url)
    hashes = URLScan.getInitialResults(result['api'])
    domains = URLScan.extactDomains(hashes)

    results = checkResults(domains)
    # Parse all responses and get all links and get TI from RiskIQ
    # write code to push to MISP
    #MISP.pushToMISP(url, results)
    return results