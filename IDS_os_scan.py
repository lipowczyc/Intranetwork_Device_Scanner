import nmap3
import json
import re
import pathlib
import datetime

""" Intranetwork Device Scanner - convenient extension for GLPI

Useful when user doesn't want to physically walk from machine to another to do scan of a computer.
It gives basic information about device, such as:
    - OS
    - mac address
    - ip address
    - host name
    - open ports
    - open services and more
Basically it gives all the information which standard nmap OS scan can give but in JSON file formatted to be 
compatible with GLPI import files.

As the opening this tool needs three information as an input:
    - absolute path to folder for saving outputs
    - name of network on which scan will be performed
    - ip address or subnet

To successfully perform a scan, on computer this script is running in, administrator privileges are needed with 
addition to installed Python 3.12 and nmap.
Scan is performed with nmap3 module, and it gives JSON file as an output of nmap os scan. 

After extracting certain data, another JSON file is created based on pattern of files which GLPI can import and read.

Author: Sylwia Postnikoff
"""


class IDSosDetect:
    default_folder_path = ""
    network_name: str = ""
    file_name: str = ""
    ip_to_scan: str = ""
    current_datetime = ""
    output_dict = {
        "network_name": "",
        "current_datetime": "",
        "scan_id": 0,
        "mac_addr": "",
        "hostname": "",
        "full_hostname": "",
        "machine_name": "",
        "machine_ip": ""
    }

    def start(self):
        self.initial_info()
        self.do_scan()
        self.collect_data()
        self.give_output(IDSosDetect.output_dict)

    def initial_info(self):
        user_input_path = pathlib.Path(str(input('Enter place to save data - absolute: path/to/your/folder : \n')))
        self.check_path(user_input_path)
        default_folder_path = pathlib.Path.joinpath(user_input_path, "netdiscovery")
        self.check_path(default_folder_path)
        IDSosDetect.default_folder_path = default_folder_path
        IDSosDetect.network_name = str(input("Enter network/company name: "))
        timestamp = datetime.datetime.now()
        IDSosDetect.current_datetime = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        stamp_for_file = timestamp.strftime("%y%m%d_%H_%M")
        IDSosDetect.file_name = pathlib.Path.joinpath(default_folder_path, f"IDS_OS_scan_{stamp_for_file}.json")
        ip_is_correct = False
        while not ip_is_correct:
            user_input = str(input("Enter an ip address to scan or subnet: "))
            ip_is_correct = self.check_ip(user_input)
            if not ip_is_correct:
                print("Address is incorrect, try again")
        IDSosDetect.ip_to_scan = user_input

    @staticmethod
    def check_path(path):
        if not path.exists():
            path.mkdir(exist_ok=True)
            print(f"Folder '{path}' created.")
        else:
            print(f"Folder '{path.exists()}' already exists.")

    @staticmethod
    def do_scan():
        nmap = nmap3.Nmap()
        with open(IDSosDetect.file_name, "w") as outfile:
            os_results = nmap.nmap_os_detection(IDSosDetect.ip_to_scan)
            json.dump(os_results, outfile, indent=4)

    def collect_data(self):
        with open(IDSosDetect.file_name, "r") as new_file:
            scan_id = 1
            os_results_from_file = json.load(new_file)
            for result_key, result_value in os_results_from_file.items():
                if self.check_ip(result_key):
                    ip_add = result_key
                if result_key is ip_add:
                    if self.check_result_value(result_value):
                        mac_addr, mac_vendor = self.get_macinfo(result_value)
                        hostname, full_hostname = self.get_hostname(result_value, ip_add)

                        result_os = self.os_match(result_value)
                        if result_os:
                            for list_item in range(1):
                                machine_name = result_os[list_item].get("name")
                        else:
                            if mac_vendor:
                                machine_name = mac_vendor
                            else:
                                machine_name = "not found"
                        up_out_dict = {
                            "network_name": IDSosDetect.network_name,
                            "current_datetime": IDSosDetect.current_datetime,
                            "scan_id": scan_id,
                            "mac_addr": mac_addr,
                            "hostname": hostname,
                            "full_hostname": full_hostname,
                            "machine_name": machine_name,
                            "machine_ip": ip_add
                        }
                        scan_id += 1
                        IDSosDetect.output_dict.update(up_out_dict)

    @staticmethod
    def check_ip(key):
        ip_patt = (r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                   r"([/][0-3][0-2]?|[/][1-2][0-9]|[/][0-9])?$")
        match_ip = re.findall(ip_patt, key)
        if match_ip:
            return True
        else:
            return False

    @staticmethod
    def check_result_value(value):
        empty_result = {'osmatch': {}, 'ports': [], 'hostname': [], 'macaddress': None}
        if value != empty_result:
            return True

    @staticmethod
    def get_macinfo(value):
        macinfo = value.get("macaddress")
        if macinfo:
            result_addr = macinfo.get("addr")
            result_vendor = macinfo.get("vendor")
            if result_vendor:
                result_vendor = result_vendor
            else:
                result_vendor = "not found"
        else:
            result_addr = "00:00:00:00:00:00"
            result_vendor = "not found"
        return [result_addr, result_vendor]

    @staticmethod
    def get_hostname(value, ip_addr):
        hostname_list = value.get("hostname")
        if hostname_list:
            for it_em in range(1):
                full_host = hostname_list[it_em].get("name")

                split_hostname = full_host.split(".")
            host = split_hostname[0]
        else:
            host = ip_addr
            full_host = "not found"
        return [host, full_host]

    @staticmethod
    def os_match(value):
        osmatch = value.get("osmatch")
        return osmatch

    @staticmethod
    def give_output(dicto):
        pattern_dictionary = {
            "action": "inventory",
            "content": {
                "accesslog": {
                    "logdate": dicto["current_datetime"]
                },
                "hardware": {
                    "name": dicto["hostname"]
                },
                "networks": [
                    {
                        "description": "eth0",
                        "ipaddress": dicto["machine_ip"],
                        "mac": dicto["mac_addr"]
                    }
                ],
                "operatingsystem": {
                    "fqdn": dicto["full_hostname"],
                    "full_name": dicto["machine_name"]
                },
                "versionclient": "GLPI-Inventory_v1.5-1"
            },
            "deviceid": f"{dicto["network_name"]}_{dicto["scan_id"]}",
            "itemtype": "Computer"
        }

        device_file_name = pathlib.Path.joinpath(IDSosDetect.default_folder_path, f"{dicto["machine_ip"]}.json")
        with open(device_file_name, "w") as id_file:
            json.dump(pattern_dictionary, id_file, indent=4)


def begin_process():
    cu_object = IDSosDetect()
    cu_object.start()


begin_process()
