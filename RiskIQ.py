import requests
import keys

def passivetotal_get(path, query):
    url = keys.RiskIQbase_url + path
    data = {'query': query}
    # Important: Specifying json= here instead of data= ensures that the
    # Content-Type header is application/json, which is necessary.
    response = requests.get(url+"?query="+query, auth=keys.RiskIQauth, json=data)
    # This parses the response text as JSON and returns the data representation.
    return response.json()


def checkScore(domain):
    pdns_results = passivetotal_get('/v2/reputation', domain)
    if 'score' not in pdns_results:
        return -1
    elif pdns_results['score'] > keys.RiskIQScore:
        return pdns_results['score']
    else:
        return -1

