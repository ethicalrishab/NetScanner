#Importing Modules
import scapy.all as scapy
import threading
from colorama import Fore
import socket

#Fetching Current Interface IP
our_ip=socket.gethostbyname(socket.gethostname())
our_ip_octet=our_ip[:our_ip.rfind(".")+1]

#List To Store All Threads
threads=[]

#Printing Banner
print(Fore.YELLOW+'''
 _   _      _                      _        _____                                 
| \ | |    | |                    | |      /  ___|                                
|  \| | ___| |___      _____  _ __| | __   \ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /    `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <    /\__/ / (_| (_| | | | | | | |  __/ |   
\_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\   \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                
                                                    By @daredevil_rishab          
                                                    --------------------          
''')

#Printing Table
print(Fore.RED+"IP Address\t\t\tMAC Address")
print(Fore.WHITE+"----------\t\t\t-----------\n\n")

#Function To Check Ip & It's MAC
def check(target):
    arp=scapy.ARP(pdst=target)
    brodcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet=brodcast/arp
    answered,unanswered=scapy.srp(final_packet,timeout=10,verbose=False)
    if answered:
        for element in answered:
            print(Fore.GREEN+element[1].psrc+"\t\t\t"+element[1].hwsrc)

#Starting Threads For Each Possible Ip
for last_octet in range(1,256):
    ip=our_ip_octet+str(last_octet)
    t=threading.Thread(target=check,args=(ip,))
    t.start()
    threads.append(t)

#Waiting For Threads To Be Finished
for t in threads:
    t.join()

#Holding Terminal
print()
print(Fore.BLUE+"[#] Scan Completed! ")
input()