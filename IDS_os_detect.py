import nmap3
import json
import re
import datetime
import pprint

# folder_path = str(input('Enter absolute: path/to/your/folder : '))
# # D:\\Users\\lipow\\PycharmProjects\\Intranetwork_Device_Scanner\\dupa
# if not os.path.exists(folder_path):
#     os.mkdir(folder_path)
#     print(f"Folder '{folder_path}' created.")
# else:
#     print(f"Folder '{folder_path}' already exists.")
#
# default_IDS_folder_path = folder_path+"/netdiscovery"
#
# if not os.path.exists(folder_path):
#     os.mkdir(default_IDS_folder_path)
#     print(f"Folder netdiscovery created in {folder_path}")
# else:
#     print(f"Folder netdiscovery already exists.")
# network_name = str(input("Enter network/company name: "))
network_name = "Efferta"
timestamp = datetime.datetime.now()
# current_datetime = timestamp.strftime("%Y-%m-%d %H:%M:%S")
nmap = nmap3.Nmap()
ip_to_scan = "192.168.7.0/24"  # str(input("Enter an ip address to scan or subnet: ")


def ids_os():
    file_name = "D:\\Sylwia\\python\\IDS\\IDS_OS_scan_0.json"
    # with open(file_name, "w") as outfile:
    #     os_results = nmap.nmap_os_detection(ip_to_scan)
    #     json.dump(os_results, outfile, indent=4)

    with open(file_name, "r") as new_file:
        os_results_from_file = json.load(new_file)
        # print(os_results_from_file)
        ip_patt = r'[0-9]+(?:\.[0-9]+){3}'
        empty_result = {'osmatch': {}, 'ports': [], 'hostname': [], 'macaddress': None}
        scan_id = 1
        for result_key, result_value in os_results_from_file.items():
            if re.findall(ip_patt, result_key):
                ip_add = result_key
            if result_key is ip_add:
                current_datetime = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                if result_value != empty_result:
                    # print(ip_add)
                    macaddress = result_value.get("macaddress")
                    if macaddress:
                        addr = macaddress.get("addr")
                        vendor = macaddress.get("vendor")
                        if vendor:
                            vendor = vendor
                        else:
                            vendor = "not found"
                    else:
                        addr = "00:00:00:00:00:00"

                    hostname_list = result_value.get("hostname")
                    if hostname_list:
                        for it_em in range(1):
                            hostname = hostname_list[it_em].get("name")
                    else:
                        hostname = ip_add

                    osmatch = result_value.get("osmatch")
                    if osmatch:
                        for list_item in range(1):  # range(len(osmatch))
                            item_name = osmatch[list_item].get("name")

                    else:
                        if vendor:
                            item_name = vendor
                        else:
                            item_name = "not found"

                    pattern_dictionary = {
                        "action": "inventory",
                        "content": {
                            "accesslog": {
                                "logdate": current_datetime  # variable with date: "2024-11-05 20:41:55"
                            },
                            "hardware": {
                                "name": hostname
                            },
                            "networks": [
                                {
                                    "description": "eth0",
                                    "ipaddress": ip_add,
                                    "mac": addr
                                }
                            ],
                            "operatingsystem": {
                                # "dns_domain": "",  # eg "mawi.local"
                                "fqdn": hostname,  # eg  "mawitech.mawi.local"
                                "full_name": item_name
                            },
                            "versionclient": "GLPI-Inventory_v1.5-1"
                        },
                        "deviceid": f"{network_name}_{scan_id}",  # f"{network_name}_{scan_id}"
                        "itemtype": "Computer"
                    }
                    scan_id += 1
                    # device_file_name = f"D:\\Sylwia\\python\\IDS\\{ip_add}.json"
                    # with open(device_file_name, "w") as id_file:
                    #     json.dump(pattern_dictionary, id_file, indent=4)

                    print(f"{ip_add}: {pattern_dictionary}")
                    # pprint.pprint(pattern_dictionary, )


ids_os()
