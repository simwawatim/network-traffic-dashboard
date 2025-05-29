import requests

url = "https://api.ipapi.com/161.185.160.93?access_key=1f4521d9dad629fc017125a079c50709"


response = requests.get(url)

print(response.json())