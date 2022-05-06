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

    def idsWarnLoggingTcp(self,packetinfo,protocol): # IDS모드의 Rule Set에 탐지된 TCP패킷 로그를 남기는 함수
        
        self.logger.warn(f"- WARN - {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| |Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Seq={packetinfo[4]} Ack={packetinfo[5]} Flag={packetinfo[6]} Win={packetinfo[7]} Len={packetinfo[8]} ")
        

    def idsWarnLoggingUdp(self,packetinfo,protocol): # IDS모드의 Rule Set에 탐지된 UDP패킷로그를 남기는 함수 
        
        
        self.logger.warn(f"- WARN - {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| |Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Len={packetinfo[4]} ")
        

    def idsInfoLoggingTcp(self,packetinfo,protocol): # IDS모드의 Rule Set에 탐지되지 않은 TCP패킷 로그를 남기는 함수
        
        
        self.logger.info(f"- Info - {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| |Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Seq={packetinfo[4]} Ack={packetinfo[5]} Flag={packetinfo[6]} Win={packetinfo[7]} Len={packetinfo[8]} ")
        

    def idsInfoLoggingUdp(self,packetinfo,protocol): # IDS모드의 Rule Set에 탐지되지 않은 UDP패킷 로그를 남기는 함수
    
        
        self.logger.info(f"- Info - {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| |Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Len={packetinfo[4]} ")
              

    def tcpMonitoringLog(self,packetinfo,protocol,count): # PacketMonitoring모드의 TCP패킷 로그를 남기는 함수


        self.logger.info(f"No.{count} {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| |Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Seq={packetinfo[4]} Ack={packetinfo[5]} Flag={packetinfo[6]} Win={packetinfo[7]} Len={packetinfo[8]} ")


    def udpMonitoringLog(self,packetinfo,protocol,count): # PacketMonitoring모드의 UDP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Source IP={packetinfo[0]} -> Destination IP={packetinfo[1]}| | Source Port={packetinfo[2]} -> Destination Port={packetinfo[3]}| Len={packetinfo[4]} ")

    
    def icmpMonitoringLog(self,packetinfo,protocol,count): # PacketMonitoring모드의 ICMP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Source MAC={packetinfo[0]} -> Destination MAC={packetinfo[1]}| |Source IP={packetinfo[2]} -> Destination Port={packetinfo[3]}| Type={packetinfo[4]} TTL={packetinfo[5]} Id={packetinfo[6]} seq={packetinfo[7]} len={packetinfo[8]} ")


    def arpMonitoringLog(self,packetinfo,protocol,count): # PacketMonitoring모드의 ARP패킷 로그를 남기는 함수

       
        self.logger.info(f"No.{count} {protocol} |Send MAC={packetinfo[0]} -> Target MAC={packetinfo[1]}| |Send IP={packetinfo[2]} -> Target Port={packetinfo[3]}| Type={packetinfo[4]} Operation={packetinfo[5]} len={packetinfo[6]} ")