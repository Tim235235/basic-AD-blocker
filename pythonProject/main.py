import mitmproxy
from mitmproxy import http
from adblockparser import AdblockRules
import requests

#mitmdump -p 8080 -s main.py
#mitmproxy -p 8888
#mitmdump -s main.py
#mitmdump -p 8080 -s main.py -q


def auto_update_ad_filter(url):
    response = requests.get(url)
    response.raise_for_status()
    return [line for line in response.text.splitlines()
            if line and not line.startswith("!") and not line.startswith("@@")
            and "#?#" not in line and "#@#" not in line]


raw_ad_rules = auto_update_ad_filter("https://easylist.to/easylist/easylist.txt")
raw_tracker_rules = auto_update_ad_filter("https://easylist.to/easylist/easyprivacy.txt")
ad_filter = raw_ad_rules + raw_tracker_rules
rules = AdblockRules(ad_filter)


def request(flow: http.HTTPFlow):
    try:
        if rules.should_block(flow.request.pretty_url):
            print(f"Blocked: {flow.request.pretty_url}")
            flow.kill()
    except Exception as e:
        print(f"Error processing {flow.request.pretty_url}: {e}")
