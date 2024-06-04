import requests
import keys

def getURLRep(URL):
    results = -1

#    url = "http://bytetip-boe.bytedance.net/api/v1/domain/"+URL+"/aggregated_ioc"
    url = "https://bytetip.byteintl.net/api/v1/domain/"+URL+"/aggregated_ioc"
    headers = {
        "accept": "application/json",
        "cti-token": keys.ByteTIAPI
    }
    response = requests.get(url, headers=headers, verify=False)
    textRepsponse = response.json()
    try:
        results = textRepsponse["data"]["is_malicious"]
        # 1 - Malicious
        if results:
            return 1
        else:
            return 0
    except Exception as e:
        print (str(textRepsponse))
    return results