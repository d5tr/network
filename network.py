import socket 
print('''
    _   _______________       ______  ____  __ __        
   / | / / ____/_  __/ |     / / __ \/ __ \/ //_/        
  /  |/ / __/   / /  | | /| / / / / / /_/ / ,<     ______
 / /|  / /___  / /   | |/ |/ / /_/ / _, _/ /| |   /_____/
/_/ |_/_____/ /_/    |__/|__/\____/_/ |_/_/ |_|

    ____  ________________
   / __ \/ ____/_  __/ __ \
  / / / /___ \  / / / /_/ /
 / /_/ /___/ / / / / _, _/
/_____/_____/ /_/ /_/ |_|

########################
#[1]port scan          #
#[2]get ip web site    #
#[3]get your ip        #
#[4]get info for ip    #
#[5]sniff wifi         #  
########################
''')
cho = int(input("enter number you went :"))
if cho == 1:
    host = input('rhost: ')
    try:
        for port in range(1,1000):
            s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((host,port))
            if result == 0: 
                def non():
                    print('------------------')
                print("port {} is open. ".format(port))
                non()
    except:
        print("erorr")

elif cho == 2 :
    ip = socket.gethostbyname(input("enter url :"))

    print ("ip adresss :" +" "+ ip)


elif cho == 3 :
    def find_id():
        host = socket.gethostname()
        ip_add = socket.gethostbyname(host)

        print(f'host : {host}')
        print(f'IP Address : {ip_add}')

    if __name__ == '__main__':
        find_id()
elif cho == 4:
    print('''
    #################################################
    # you most install geoip and geolite2           #
    # serch in youtube how install geoip in python3 #
    #################################################
    ''')
    from geoip import geolite2
    ip = input("enter ip : ")
    local = geolite2.lookup(ip)

    if local is None :
        print("unkonwn")

    else:
        print (local)

elif cho == 5:
    from scapy.all import *

    def analyzer(pkt):
        if pkt.haslayer(TCP):
            print("===============================")
            print("<<< TCP ! >>>")
            src_ip = pkt[IP].src   #الايبي 
            dst_ip = pkt[IP].dst
            mac_src = pkt.src     #الماك ادرس 
            mac_dst = pkt.dst
            src_port = pkt.sport  #البورت الي طلع منه
            dst_port = pkt.dport
            print("mac_src = "+mac_src)
            print("mac_dst = "+mac_dst)
            print("+")
            print("src = "+src_ip)
            print("dst = "+dst_ip)
            print("+")
            print("src_port = "+ str(src_port))
            print("dst_port = "+ str(dst_port))
            if pkt.haslayer (Raw):
                print(pkt[Raw].load)
            print("packet_size = "+ str(len(pkt[TCP])))
            print("================================")
        elif pkt.haslayer(UDP):
            print("================================")
            print("<<< UDP ! >>>")
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            mac_src = pkt.src
            mac_dst = pkt.dst
            src_port = pkt.sport  #البورت الي طلع منه
            dst_port = pkt.dport
            print("mac_src = "+mac_src)
            print("mac_dst ="+mac_dst)
            print("+")
            print("src_ip = "+src_ip)
            print("dst_ip = "+dst_ip)
            print("+")
            print("src_port = "+ str(src_port))
            print("dst_port = "+ str(dst_port))
            if pkt.haslayer (Raw):
                print(pkt[Raw].load)
            print("packet_size = "+ str(len(pkt[UDP])))
            print("===============================")
    
   
    print("*********START*********")
    sniff(iface=input('enter your network name : '),prn=analyzer)