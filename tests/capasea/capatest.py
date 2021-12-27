import json
import requests

capa_url_json = '{"report":"./reports/PushPull.52bf94dad049745a232b6063fafbda56"}'
jsonObj = json.loads(capa_url_json)

res = requests.get("http://127.0.0.1:8080" + jsonObj["report"][1:])

print(res.json())

