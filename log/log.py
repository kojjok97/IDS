import logging
import datetime
import os

class Log:

    def __init__(self,name):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.format = logging.Formatter("%(asctime)s : %(message)s")


        if name != 'no' and name != 'ids': # PacketMonitoring모드로 실행하면서 파일인자를 사용했을 경우
        
            self.file_handler_mon = logging.FileHandler(filename="./{}".format(name))
            self.file_handler_mon.setFormatter(self.format)
            self.file_handler_mon.setLevel(logging.INFO)
            self.logger.addHandler(self.file_handler_mon)
            self.console_mon = logging.StreamHandler()
            self.console_mon.setFormatter(self.format)
            self.console_mon.setLevel(logging.INFO)
            self.logger.addHandler(self.console_mon)

        elif name == 'ids': # IDS모드로 실행했을 경우
            date = datetime.datetime.now()
            if 'logs' not in os.listdir('./'):
                os.makedirs('logs')
            self.file_handler_ids_info = logging.FileHandler(filename="./logs/{}_{}_{}.log".format(date.year,date.month,date.day))
            self.file_handler_ids_info.setFormatter(self.format)
            self.file_handler_ids_info.setLevel(logging.INFO)
            self.logger.addHandler(self.file_handler_ids_info)

            self.console_ids = logging.StreamHandler()
            self.console_ids.setFormatter(self.format)
            self.console_ids.setLevel(logging.WARN)
            self.logger.addHandler(self.console_ids)

        else: #PacketMonitoring모드로 실행하면서 파일인자를 사용하지 않았을 경우
    
            self.console_mon = logging.StreamHandler()
            self.console_mon.setFormatter(self.format)
            self.console_mon.setLevel(logging.INFO)
            self.logger.addHandler(self.console_mon)    

    def ids_warn_logging_tcp(self,packet_info,protocol): # IDS모드의 Rule Set에 탐지된 TCP패킷 로그를 남기는 함수
        
        self.logger.warn(f"- WARN - {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| |Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Seq={packet_info[4]} Ack={packet_info[5]} Flag={packet_info[6]} Win={packet_info[7]} Len={packet_info[8]} ")
        

    def ids_warn_logging_udp(self,packet_info,protocol): # IDS모드의 Rule Set에 탐지된 UDP패킷로그를 남기는 함수 
        
        
        self.logger.warn(f"- WARN - {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| |Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Len={packet_info[4]} ")
        

    def ids_info_logging_tcp(self,packet_info,protocol): # IDS모드의 Rule Set에 탐지되지 않은 TCP패킷 로그를 남기는 함수
        
        
        self.logger.info(f"- Info - {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| |Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Seq={packet_info[4]} Ack={packet_info[5]} Flag={packet_info[6]} Win={packet_info[7]} Len={packet_info[8]} ")
        

    def ids_info_logging_udp(self,packet_info,protocol): # IDS모드의 Rule Set에 탐지되지 않은 UDP패킷 로그를 남기는 함수
    
        
        self.logger.info(f"- Info - {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| |Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Len={packet_info[4]} ")
              

    def tcp_monitoring_log(self,packet_info,protocol,count): # PacketMonitoring모드의 TCP패킷 로그를 남기는 함수


        self.logger.info(f"No.{count} {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| |Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Seq={packet_info[4]} Ack={packet_info[5]} Flag={packet_info[6]} Win={packet_info[7]} Len={packet_info[8]} ")


    def udp_monitoring_log(self,packet_info,protocol,count): # PacketMonitoring모드의 UDP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Source IP={packet_info[0]} -> Destination IP={packet_info[1]}| | Source Port={packet_info[2]} -> Destination Port={packet_info[3]}| Len={packet_info[4]} ")

    
    def icmp_monitoring_log(self,packet_info,protocol,count): # PacketMonitoring모드의 ICMP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Source MAC={packet_info[0]} -> Destination MAC={packet_info[1]}| |Source IP={packet_info[2]} -> Destination Port={packet_info[3]}| Type={packet_info[4]} TTL={packet_info[5]} Id={packet_info[6]} seq={packet_info[7]} len={packet_info[8]} ")


    def arp_monitoring_log(self,packet_info,protocol,count): # PacketMonitoring모드의 ARP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Send MAC={packet_info[0]} -> Target MAC={packet_info[1]}| |Send IP={packet_info[2]} -> Target Port={packet_info[3]}| Type={packet_info[4]} Operation={packet_info[5]} len={packet_info[6]} ")