import socket 
from struct import * 
import binascii
from rule_set import ids_rule_set
from log import log
import sys
import threading 
import time

TCP = 6
UDP = 17

def tlanslation_flag(flagbit): # 16진수로 되어있는 flags를 계산하여 문자로 반환하는 함수

    flagbit = str(bin(flagbit))[::-1]

    flags = ['F','S','R','P','A','U']

    flag = ''

    for i in range(len(flagbit[:-2])):
        if flagbit[i] == '1':
            flag += flags[i]
        else:
            continue

        

    return flag


    
class Ids: # IDS와 PacketMonitoring의 클래스

    def __init__(self):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0800)) # TCP,UDP,ICMP를 받는 소켓 
        self.arps = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0806)) # ARP를 받는 소켓 
        self.logger = log.Log('ids')
        self.count = 1
        self._lock = threading.Lock()


    def ids(self):
        
        ids_rule_set.read_rule() # IDS동작 전 Rule set을 읽어 변수에 담는다
        
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

                flags = tlanslation_flag(tcp_header[5])         # Flags
                window = tcp_header[6]                         # Window
                
                warn = ids_rule_set.check_rule(dst_port,src_ip_addr,dst_ip_addr)  # Rule set에 탐지되는지를 판별하여 룰셋과 일치하면 True 일치하지 않으면 Flase 반환
                
                if warn == True:
                    self.logger.ids_warn_logging_tcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")      # 탐지된 패킷을 로그로 남기는 함수 
                else:
                    self.logger.ids_info_logging_tcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")      # 탐지되지 않은 패킷을 로그로 남기는 함수

            elif protocol == UDP:                              # UDP 패킷 
                udp_header = data[34:42]                       
                udp_header = unpack('!HHHH',udp_header)        # TCP Header구조에 맞춰 리스트로 필드 반환 
                src_port = udp_header[0]                       # 출발지 포트 번호 
                dst_port = udp_header[1]                       # 목적지 포트 번호

                warn = ids_rule_set.check_rule(dst_port,src_ip_addr,dst_ip_addr)

                if warn == True:
                    self.logger.ids_warn_logging_udp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")      # 탐지된 패킷을 로그로 남기는 함수 
                else:
                    self.logger.ids_info_logging_udp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")      # 탐지되지 않은 패킷을 로그로 남기는 함수
