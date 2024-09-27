import requests
import os
from io import BytesIO

root_url = "http://localhost:8880"

def upload_file():
    url=f"{root_url}/"
    files = {'file': open('./test.txt', 'rb')}
    response = requests.post(url, files=files)
    print(response.text)

upload_file()
