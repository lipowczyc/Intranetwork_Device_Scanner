import nmap

scanner = nmap.PortScanner()
print("Intranet Device Scanner")
print("<", "."*20, ">")

ip_addr = input("Enter the IP you want to scan: ")
print(f"The IP you entered is: {ip_addr}")
type(ip_addr)
choosing_scan_type = input("""
\nChoose 
""")
