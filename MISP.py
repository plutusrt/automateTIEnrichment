from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp import ThreatLevel
import keys

def pushToMISP(domain, results):
    # Create a PyMISP instance
    misp = PyMISP(keys.misp_url, keys.misp_key, keys.misp_verifycert)

    # Create a new MISP event
    event = MISPEvent()

    # Set event threat level
    event.threat_level_id = ThreatLevel.low

    # Set event attributes
    event.info = domain + " related IOCs found"
    event.add_tag('Phishing')  # Add tags as needed

    # Add attributes to the event
    for domain in results:
        event.add_attribute('domain', domain)  # Change the type and value accordingly

    # Add the event to MISP
    misp.add_event(event)
