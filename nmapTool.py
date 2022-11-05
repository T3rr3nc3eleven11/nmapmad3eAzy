import nmap
import os
import sys

print("[-] nmap python Automation by T3rr3nc3 3L3v3n11")

print("<------------------------------------------------------------------------------------------------------------>")
print("<----------  -------- --------    -------- --------   --------   --------  --------  ---  ---------  -------->")
print("<----------  -------- ----  ----  -------- ----  ---- ----  ---- --------  --------  ---  ---------  -------->")
print("<  ----      -----    ----  ----  ------   ----  ---- ----  ---- ------    ----  --  ---  ---------  ------  >")
print("<  ----      -------- --------    -------- --------   --------   --------  ----  --  ---  ----       -------->")
print("<  ----      -------- ----------  -------- ---------  ---------  --------  ----  --  ---  ----       -------->")
print("<  ----      ------   ----- ----  ------   ----  ---- ----  ---- ------    ----  --  ---  ----       ------  >")
print("<  ----      -------- ----   ---  -------- ----   --- ----   --- --------  ----  -------  ---------  -------->")
print("<  ----      -------- ----   ---  -------- ----   --- ----   --- --------  ----  -------  ---------  -------->")
print("<------------------------------------------------------------------------------------------------------------>")
print("\n")
print("\n")
print("\n")
print("Would you like a custom scan or a script kiddie scan. YES for custom scan, NO for script kiddie scan. ")
scantype = input("N(No) and Y(Yes): ")
print("\n")
print("\n")


def helpOptions():
	print("\n")
	print("[-] Usage: Eleven.py -A [scan_type *3 options] -IP [target_host or range_ip_addresses] -P [port_number_or_range_ports]")
	print("\n")
	print("[-] Examples: ")
	print("[-] nmapTool.py -A -T4 -O 192.168.19.1 -p 0 1024")
	print("[-] nmapTool.py -sS -Pn   192.168.19.1 -p 0 1024")
	print("[-] nmapTool.py -sV -f 192.168.19.1 -p 0 1024")
	print("\n")
	print("\n")


def main():
	print("[-] Script kiddie Option!!!!!!!!!!!!!!!!!!!!!!!!!")
	print("<   ---------    ----   -----     ----------     >")
	print("<   ---------    ----   -----   -------------    >")
	print("<   ------       ----  ------ ---  ------  ----  >")
	print("<   ---------    -----------  ------------------ >")
	print("<   ---------    ----------   ---- ------- ----- >")
	print("<       -----    ----   -----  ---         ----- >")
	print("<   ---------    ----    ----    -------------   >")
	print("<   ---------    ----    ----     -----------    >")

	print("[-]Please Enter the type of scan you want to run.")
	print("\n")
	print("\n")

	options  = (input(
			"\n[1] service version, port scan and target specification  "
			"\n[2] OS Detection, IDS Evasion	"
			"\n[3] target specification, Host Discovery "))
	ipAddress = str(input("Enter the ipAddress: "))



	if str(1) in options:
		command = "nmap " + "-sV " + "-p 1-1024 " + ipAddress
		process = os.popen(command)
		results = str(process.read())
		print(results)
		sys.exit()

	if str(2) in options:
		command = "nmap " + "-O " + "-f " + ipAddress
		process = os.popen(command)
		results = str(process.read())
		print(results)
		sys.exit()

	if str(3) in options:
		command = "nmap " + "-sL " + ipAddress
		process = os.popen(command)
		results = str(process.read())
		print(results)
		sys.exit()



def customscan():
	print("\n")
	print("Example:  ")
	print("\n")
	print("Enter option: -A ")
	print("Enter option: -sS ")
	print("Enter option: -O ")
	print("Enter IP Address or IP Address range: 192.168.1.1-250 ")
	print("Enter port number or port range: 1-1023")
	print("\n")
	print("\n")
	option1 = str(input("Enter option: "))
	option2 = str(input("Enter option: "))
	option3 = str(input("Enter option: "))
	Ip		= str(input("Enter IP Address or IP Address range: "))
	ports	= str(input("Enter port number or port range: "))

	command = "nmap " + option1 + " " +option2 + " "+ option3 + " "+ ports +" "+ Ip
	process = os.popen(command)
	results = str(process.read())
	print(results)
	sys.exit()

if "Y" and "y" in scantype:
	customscan()
elif "N" and "n" in scantype:
	main()
else:
	helpOptions()
