import requests

files = {'myFile': ("example", open("/path/to/file", 'rb'))}
res = requests.post("http://<ip_addr>:8080/upload", files=files)
if res.status_code == 200:
    data = res.json()
    print(data)

