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
Scan is performed with nmap3 module, and it gives Json file as an output of nmap os scan. 

After extracting certain data, another json file is created based on pattern of files which GLP can import and read.

"""
