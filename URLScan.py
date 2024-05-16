import csv

import requests
import json
import keys
import time

def submitURL(url):
    headers = {'API-Key':keys.URLScanAPIKey,'Content-Type':'application/json'}
    data = {"url": url, "visibility": "private"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    return response.json()

def getInitialResults(url):
    payload = {}
    whitelist = ["stripe.com", "fonts.googleapis.com", "fonts.gstatic.com"]
    results = {}
    toRemove = []
    headers = {'API-Key':keys.URLScanAPIKey, 'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers)
    while (response.status_code == 404):
        time.sleep(10)
        response = requests.get(url, headers=headers)
    resultsFromURLScan = response.json()
    for i in range(0,len(resultsFromURLScan['lists']['hashes'])):
        try:
            results[resultsFromURLScan['lists']['hashes'][i]] = resultsFromURLScan['lists']['urls'][i]
        except:
            if len(resultsFromURLScan['lists']['urls']) < i+1:
                results[resultsFromURLScan['lists']['hashes'][i]] = ""
    for k,v in results.items():
        for item in whitelist:
            if item in v:
                toRemove.append(k)
    for item in toRemove:
        del results[item]
    return results

def extactDomains(hashes):
    domains = []
    url = keys.URLScanBaseURL + "hash:"
    payload = {}
    headers = {'API-Key':keys.URLScanAPIKey, 'Content-Type': 'application/json'}
    with open('output/domains.csv', 'w') as fp:
        csvWriter = csv.writer(fp)
        csvWriter.writerow(["hash", "url", "domain", "urlscan", "screenshot"])
        for hash, scannedUrl in hashes.items():
            response = requests.get(url+hash, headers=headers)
            try:
                resultsFromURLScan = response.json()
                for item in resultsFromURLScan['results']:
                    if item['task']['domain'] not in domains:
                        csvWriter.writerow([hash, scannedUrl, item['task']['domain'], item['result'], item['screenshot']])
                        domains.append(item['task']['domain'])
            except Exception as e:
                print (str(e))
    return domains


