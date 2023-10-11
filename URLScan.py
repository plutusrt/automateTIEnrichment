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
    headers = {'Content-Type': 'application/json'}
    response = requests.get(url, headers=headers)
    while (response.status_code == 404):
        time.sleep(10)
        response = requests.get(url, headers=headers)
    resultsFromURLScan = response.json()
    return resultsFromURLScan['lists']['hashes']

def extactDomains(hashes):
    domains = []
    url = keys.URLScanBaseURL + "hash:"
    payload = {}
    headers = {'Content-Type': 'application/json'}
    with open('output/domains.csv', 'w') as fp:
        csvWriter = csv.writer(fp)
        for hash in hashes:
            response = requests.get(url+hash, headers=headers)
            resultsFromURLScan =  response.json()
            for item in resultsFromURLScan['results']:
                if item['task']['domain'] not in domains:
                    csvWriter.writerow([item['task']['domain']])
                    domains.append(item['task']['domain'])
    return domains


