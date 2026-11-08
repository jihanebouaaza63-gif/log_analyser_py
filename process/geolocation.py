import requests
from requests import Response
import concurrent


def get_location(ip):
    response: Response = requests.get("https://ipinfo.io/" + ip + "/json/")
    if response.status_code == 200:
        print(response.json())


if __name__ == "__main__":
    print(get_location("109.199.110.135"))