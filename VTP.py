import requests
import keys
import json

def getURLRep(URL):
    results = -1
    url = "https://www.virustotal.com/api/v3/domains/"+URL
    headers = {
        "accept": "application/json",
        "x-apikey": keys.VirusTotalAPI
    }
    response = requests.get(url, headers=headers)
    textRepsponse = json.loads(response.text)
    try:
        results = int(textRepsponse['data']['attributes']['last_analysis_stats']['malicious']) + int(textRepsponse['data']['attributes']['last_analysis_stats']['suspicious'])
    except Exception as e:
        print (str(textRepsponse))
    return results