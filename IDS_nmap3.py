import nmap3
import json


nmap = nmap3.Nmap()
with open("IDS_nmap3.json", "w") as outfile:
    os_results = nmap.nmap_version_detection("192.168.7.24")
    json.dump(os_results, outfile, indent=4)


