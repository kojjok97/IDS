import argparse
from network_monitoring import network_monitoring, ids
from concurrent.futures import ThreadPoolExecutor


def argparser(): # 사용자 입력 인자 처리 

    parser = argparse.ArgumentParser(description='Process some integers')
    parser.add_argument('-i' , dest='interface', action='store', type=str, help='Specify the interface', default='any')
    parser.add_argument('-sport', dest='sport', action='store', type=int, help='Specify the source port number', default='0')
    parser.add_argument('-dport', dest='dport', action='store', type=int, help='Specify the destination port number', default='0')
    parser.add_argument('-sip', dest='sip', action='store', type=str, help='Specify the source IP number', default='any')
    parser.add_argument('-dip', dest='dip', action='store', type=str, help='Specify the destination IP number', default='any')
    parser.add_argument('-f', dest='file_path', action='store', type=str, help='Specify the file path', default='no')
    parser.add_argument('-m', dest='mode', action='store_true', help='If you use this argument, you will execute packet monitoring mode ')
    parser.add_argument('-p',dest='protocol',action='store',type=str,help='Usage : -p [tcp|udp|icmp] default=tcp', default='any') 

    args = parser.parse_args() 

    args = vars(args)
    
    if args["mode"] == False: # 인자가 없을 시 IDS 모드로 동작
        return False
    else:                     # 인자가 있다면 PacketMonitoring 모드로 동작
        return args


def main():
    args = argparser()


    if args == False:
        network_ids = ids.Ids('ids')   # IDS모드 동작 
        network_ids.ids()
    else:
        monitoring = network_monitoring.Monitor(args['file_path'])  # PacketMonitoring모드로 동작 

        with ThreadPoolExecutor(max_workers=2) as ex:
            ex.submit(monitoring.packet_filtering,args)             # TCP,UDP,ICMP 모니터링 스레드
            ex.submit(monitoring.arp_monitoring,args)               # ARP 모니터링 스레드
        

    



if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        raise
    except KeyboardInterrupt:
        print("Interrupted")


