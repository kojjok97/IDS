import socket 
from struct import * 
import logging 
import binascii
from ruleSet import ruleSet
from log import log
import sys
import threading 
import time

TCP = 6
UDP = 17

def tlanslationFlag(flagbit): # 16진수로 되어있는 flags를 계산하여 문자로 반환하는 함수

    flagbit = str(bin(flagbit))[::-1]

    flags = ['F','S','R','P','A','U']

    flag = ''

    for i in range(len(flagbit[:-2])):
        if flagbit[i] == '1':
            flag += flags[i]
        else:
            continue

        

    return flag


    
class Monitor: # IDS와 PacketMonitoring의 클래스

    def __init__(self,mode):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0800)) # TCP,UDP,ICMP를 받는 소켓 
        self.arps = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0806)) # ARP를 받는 소켓 
        self.logger = log.Log(mode)
        self.count = 1
        self._lock = threading.Lock()


    def ids(self):
        
        ruleSet.readRule() # IDS동작 전 Rule set을 읽어 변수에 담는다
        
        while(1):
            

            data = self.s.recvfrom(65565) 

            data = data[0] 
  
            ip_header = data[14:34]
            ip_header = unpack("!BBHHHBBH4s4s", ip_header) #  IP Header구조에 맞춰 리스트로 필드 반환

            src_ip_addr = socket.inet_ntoa(ip_header[8])   # 출발지 IP 주소 
            dst_ip_addr = socket.inet_ntoa(ip_header[9])   # 도착지 IP 주소
            protocol = ip_header[6]                        # protocol 필드 상위 계층의 프로토콜을 구분할 수 있다. TCP : 6, UDP : 17, ICMP : 2
            
            
            if protocol == TCP:                                # TCP 패킷     
                tcp_header = data[34:54]                        
                tcp_header = unpack("!HHLLBBHHH",tcp_header)   # TCP Header구조에 맞춰 리스트로 필드 반환 
                src_port = tcp_header[0]                       # 출발지 포트 번호 
                dst_port = tcp_header[1]                       # 목적지 포트 번호
                sequence_number = tcp_header[2]                # Sequence Number 
                acknowledgement_number = tcp_header[3]         # Acknowledgement Number 

                flags = tlanslationFlag(tcp_header[5])         # Flags
                window = tcp_header[6]                         # Window
                
                warn = ruleSet.checkRule(dst_port,src_ip_addr,dst_ip_addr)  # Rule set에 탐지되는지를 판별하여 룰셋과 일치하면 True 일치하지 않으면 Flase 반환
                
                if warn == True:
                    self.logger.idsWarnLoggingTcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")      # 탐지된 패킷을 로그로 남기는 함수 
                else:
                    self.logger.idsInfoLoggingTcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")      # 탐지되지 않은 패킷을 로그로 남기는 함수

            elif protocol == UDP:                              # UDP 패킷 
                udp_header = data[34:42]                       
                udp_header = unpack('!HHHH',udp_header)        # TCP Header구조에 맞춰 리스트로 필드 반환 
                src_port = udp_header[0]                       # 출발지 포트 번호 
                dst_port = udp_header[1]                       # 목적지 포트 번호

                warn = ruleSet.checkRule(dst_port,src_ip_addr,dst_ip_addr)

                if warn == True:
                    self.logger.idsWarnLoggingUdp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")      # 탐지된 패킷을 로그로 남기는 함수 
                else:
                    self.logger.idsInfoLoggingUdp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")      # 탐지되지 않은 패킷을 로그로 남기는 함수





    def arpMonitoring(self,args):       #ARP패킷을 모니터링하는 함수
        port_Ip = ruleSet.checkArgument(args)  # 받은 인자중 Interface, IP, Port만 확인하여 반환하는 함수
        while(1):
            

            
            data = self.arps.recvfrom(65565)
            interface = data[1][0]             # 받은 패킷의 인터페이스 확인
            packet = data[0]
            

            arp_header = packet[14:42]
            
            time.sleep(1)
            arp_header = unpack("!2s2s1s1s2s6s4s6s4s",arp_header)           # ARP Header구조에 맞춰 리스트로 필드 반환

            protocol_type = (binascii.hexlify(arp_header[1])).decode()      # Protocol type
            op_code = (binascii.hexlify(arp_header[4])).decode()            # operation code 
            src_MAC_addr = (binascii.hexlify(arp_header[5])).decode()       # Source Hardware Address 
            src_ip_addr = socket.inet_ntoa(arp_header[6])                   # Source IP Address 
            dst_MAC_addr = (binascii.hexlify(arp_header[7])).decode()       # Target Hardware Address 
            dst_ip_addr = socket.inet_ntoa(arp_header[8])                   # Target IP Addres 
            packetArray = [interface,0,0,src_ip_addr,dst_ip_addr]            
            filtering = ruleSet.compareArguments(port_Ip,packetArray)       # Interface, Source IP, Destination IP검사후 받은 인자와 일치하면 True 반환 일치하지 않으면 False 반환 
            
            if filtering == True:

                self.logger.arpMonitoringLog([src_MAC_addr,dst_MAC_addr,src_ip_addr,dst_ip_addr,  # 인자와 패킷의 정보가 일치하면 로그 출력
                protocol_type,op_code,sys.getsizeof(packet)],'ARP',self.count)
            else:
                continue

            with self._lock:
                self.count += 1



    def packetFiltering(self,args):
        port_Ip = ruleSet.checkArgument(args)        # 받은 인자중 Interface, IP, Port만 확인하여 반환하는 함수
        ruleSet.inspectProtocol(args['protocol'])    # protocol 인자가 ARP,ICMP,TCP,UDP중 제대로 입력되었는지 확인하는 함수
        

        
        while(1):
            
            
            data = self.s.recvfrom(65565)

            interface = data[1][0]             # 받은 패킷의 인터페이스 확인
            data = data[0]
            

            ethernet_header = data[0:14]
            ethernet_header = unpack("!6s6s2s",ethernet_header)              # Ethernet Header구조에 맞춰 리스트로 필드 반환

            dst_MAC_addr = (binascii.hexlify(ethernet_header[0])).decode()   # Target Ethernet Address 
            src_MAC_addr = (binascii.hexlify(ethernet_header[1])).decode()   # Source Ethernet Address


            ip_header = data[14:34]                                          
            ip_header = unpack("!BBHHHBBH4s4s", ip_header)                   # IP Header구조에 맞춰 리스트로 필드 반환
            ttl = ip_header[5]                                               # TTL


            protocol = ip_header[6]
            src_ip_addr = socket.inet_ntoa(ip_header[8])                     # Source IP Address 
            dst_ip_addr = socket.inet_ntoa(ip_header[9])                     # Source IP Address 

            
        
            
            if protocol == TCP:
                
                if args['protocol'] != 'tcp' and args['protocol'] != 'any':
                    continue
                
                tcp_header = data[34:54]
                tcp_header = unpack("!HHLLBBHHH",tcp_header)                 # TCP Header구조에 맞춰 리스트로 필드 반환
                src_port = tcp_header[0]                                     # Source Port
                dst_port = tcp_header[1]                                     # Destination Port
                sequence_number = tcp_header[2]                              # Sequence Number 
                acknowledgement_number = tcp_header[3]                       # Acknowledgement Number 

                flags = tlanslationFlag(tcp_header[5])                       # Flags 
                window = tcp_header[6]                                       # Window
                packetArray = [interface,src_port,dst_port,src_ip_addr,dst_ip_addr] 
                filtering = ruleSet.compareArguments(port_Ip,packetArray)    # Interface, Source Port, Destination Port Source IP, Destination IP 검사후 받은 인자와 일치하면 True 반환 일치하지 않으면 False 반환 
                
                if filtering == True:
                    
                    self.logger.tcpMonitoringLog([src_ip_addr,dst_ip_addr,src_port, dst_port, sequence_number,
                    acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP",self.count) # 인자와 패킷의 정보가 일치하면 로그 출력
                else:
                    continue

            elif protocol == UDP:   
                
                if args['protocol'] != 'udp' and args['protocol'] != 'any':
                    continue
                
                udp_header = data[34:42]
                udp_header = unpack("!HHHH", udp_header)                  # UDP Header구조에 맞춰 리스트로 필드 반환

                src_port = udp_header[0]                                  # Source Port
                dst_port = udp_header[1]                                  # Destination Port
                
                packetArray = [interface,src_ip_addr,dst_ip_addr,src_port,dst_port]
                filtering = ruleSet.compareArguments(port_Ip,packetArray)   # Interface, Source Port, Destination Port Source IP, Destination IP 검사후 받은 인자와 일치하면 True 반환 일치하지 않으면 False 반환
                if filtering == True:

                    self.logger.udpMonitoringLog([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],
                    "UDP",self.count)   # 인자와 패킷의 정보가 일치하면 로그 출력
                else:
                    continue
            else:
                
                if args['protocol'] != 'icmp' and args['protocol'] != 'any':
                    print('ICMP')
                    continue
                
                icmp_header = data[34:42]
                icmp_header = unpack("!BBHHH",icmp_header)               # ICMP Header구조에 맞춰 리스트로 필드 반환


                icmp_type = icmp_header[0]                               # TYPE 

                rest_of_the_header = icmp_header[3]                      # Rest of the header
                data_section = icmp_header[4]                            # Data section
                packetArray = [interface,0,0,src_ip_addr,dst_ip_addr]
                filtering = ruleSet.compareArguments(port_Ip,packetArray)   # Interface,  Source IP, Destination IP 검사후 받은 인자와 일치하면 True 반환 일치하지 않으면 False 반환
                if filtering == True:

                    self.logger.icmpMonitoringLog([src_MAC_addr,dst_MAC_addr,src_ip_addr,dst_ip_addr,icmp_type,
                    ttl,rest_of_the_header,data_section,sys.getsizeof(data)],"ICMP",self.count) # 인자와 패킷의 정보가 일치하면 로그 출력
                else:
                    continue
            
            with self._lock:
                self.count += 1
            
