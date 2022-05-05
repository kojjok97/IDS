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

def tlanslationFlag(flagbit):

    flagbit = str(bin(flagbit))[::-1]

    flags = ['F','S','R','P','A','U']

    flag = ''

    for i in range(len(flagbit[:-2])):
        if flagbit[i] == '1':
            flag += flags[i]
        else:
            continue

        

    return flag


    
class Monitor:

    def __init__(self,mode):
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0800))
        self.arps = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(0x0806))
        self.logger = log.Log(mode)
        self.count = 0
        self._lock = threading.Lock()


    def ids(self):
        
        ruleSet.readRule()
        
        while(1):
            

            data = self.s.recvfrom(65565)

            data = data[0]

            ethernet_header = data[0:14]
            ethernet_header = unpack("!6s6s2s",ethernet_header)

            # dst_MAC_addr = (binascii.hexlify(ethernet_header[0])).decode() 
            # src_MAC_addr = (binascii.hexlify(ethernet_header[1])).decode()
  
            ip_header = data[14:34]
            ip_header = unpack("!BBHHHBBH4s4s", ip_header)

            src_ip_addr = socket.inet_ntoa(ip_header[8])
            dst_ip_addr = socket.inet_ntoa(ip_header[9])
            protocol = ip_header[6]
            
            
            if protocol == TCP:
                tcp_header = data[34:54]
                tcp_header = unpack("!HHLLBBHHH",tcp_header)
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                sequence_number = tcp_header[2]
                acknowledgement_number = tcp_header[3]

                flags = tlanslationFlag(tcp_header[5])
                window = tcp_header[6]
                
                warn = ruleSet.checkRule(dst_port,src_ip_addr,dst_ip_addr)
                
                if warn == True:
                    
                    self.logger.idsWarnLoggingTcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")
                else:
                    self.logger.idsInfoLoggingTcp([src_ip_addr,dst_ip_addr,src_port,dst_port,
                    sequence_number,acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP")
            elif protocol == UDP:
                udp_header = data[34:42]
                udp_header = unpack('!HHHH',udp_header)
                src_port = udp_header[0]
                dst_port = udp_header[1]

                warn = ruleSet.checkRule(dst_port,src_ip_addr,dst_ip_addr)

                if warn == True:
                    self.logger.idsWarnLoggingUdp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")
                else:
                    self.logger.idsInfoLoggingUdp([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],"UDP")


    def arpMonitoring(self,args):
        port_Ip = ruleSet.checkArgument(args)
        while(1):
            

            
            data = self.arps.recvfrom(65565)
            interface = data[1][0]
            packet = data[0]
            

            arp_header = packet[14:42]
            
            time.sleep(1)
            arp_header = unpack("!2s2s1s1s2s6s4s6s4s",arp_header)

            protocol_type = (binascii.hexlify(arp_header[1])).decode()
            op_code = (binascii.hexlify(arp_header[4])).decode() 

            src_MAC_addr = (binascii.hexlify(arp_header[5])).decode() 
            src_ip_addr = socket.inet_ntoa(arp_header[6])
            dst_MAC_addr = (binascii.hexlify(arp_header[7])).decode() 
            dst_ip_addr = socket.inet_ntoa(arp_header[8])
            packetArray = [interface,0,0,src_ip_addr,dst_ip_addr]
            filtering = ruleSet.compareArguments(port_Ip,packetArray)
            
            if filtering == True:

                self.logger.arpMonitoringLog([src_MAC_addr,dst_MAC_addr,src_ip_addr,dst_ip_addr,
                protocol_type,op_code,sys.getsizeof(packet)],'ARP',self.count)
            else:
                continue

            with self._lock:
                self.count += 1



    def packetFiltering(self,args):
        port_Ip = ruleSet.checkArgument(args)
        ruleSet.inspectProtocol(args['protocol'])
        

        
        while(1):
            
            
            data = self.s.recvfrom(65565)

            interface = data[1][0]
            data = data[0]
            

            ethernet_header = data[0:14]
            ethernet_header = unpack("!6s6s2s",ethernet_header)

            dst_MAC_addr = (binascii.hexlify(ethernet_header[0])).decode() 
            src_MAC_addr = (binascii.hexlify(ethernet_header[1])).decode() 


            ip_header = data[14:34]
            ip_header = unpack("!BBHHHBBH4s4s", ip_header)



            protocol = ip_header[6]
            src_ip_addr = socket.inet_ntoa(ip_header[8])
            dst_ip_addr = socket.inet_ntoa(ip_header[9])

            
        
            
            if protocol == 6:
                
                if args['protocol'] != 'tcp' and args['protocol'] != 'any':
                    continue
                
                tcp_header = data[34:54]
                tcp_header = unpack("!HHLLBBHHH",tcp_header)
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                sequence_number = tcp_header[2]
                acknowledgement_number = tcp_header[3]

                flags = tlanslationFlag(tcp_header[5])
                window = tcp_header[6]
                packetArray = [interface,src_port,dst_port,src_ip_addr,dst_ip_addr]
                filtering = ruleSet.compareArguments(port_Ip,packetArray)
                
                if filtering == True:
                    
                    self.logger.tcpMonitoringLog([src_ip_addr,dst_ip_addr,src_port, dst_port, sequence_number,
                    acknowledgement_number,flags,window,sys.getsizeof(data)],"TCP",self.count)
                else:
                    continue

            elif protocol == 17:   
                
                if args['protocol'] != 'udp' and args['protocol'] != 'any':
                    print("UDP")
                    continue
                
                udp_header = data[34:42]
                udp_header = unpack("!HHHH", udp_header)

                src_port = udp_header[0]
                dst_port = udp_header[1]
                
                packetArray = [interface,src_ip_addr,dst_ip_addr,src_port,dst_port]
                filtering = ruleSet.compareArguments(port_Ip,packetArray)
                if filtering == True:

                    self.logger.udpMonitoringLog([src_ip_addr,dst_ip_addr,src_port,dst_port,sys.getsizeof(data)],
                    "UDP",self.count)
                else:
                    continue
            else:
                
                if args['protocol'] != 'icmp' and args['protocol'] != 'any':
                    print('ICMP')
                    continue
                
                icmp_header = data[34:42]
                icmp_header = unpack("!BBHHH",icmp_header)
                ttl = ip_header[5]

                icmp_type = icmp_header[0]
                
                id = icmp_header[3]
                seq = icmp_header[4]
                packetArray = [interface,0,0,src_ip_addr,dst_ip_addr]
                filtering = ruleSet.compareArguments(port_Ip,packetArray)
                if filtering == True:

                    self.logger.icmpMonitoringLog([src_MAC_addr,dst_MAC_addr,src_ip_addr,dst_ip_addr,icmp_type,
                    ttl,id,seq,sys.getsizeof(data)],"ICMP",self.count)
                else:
                    continue
            
            with self._lock:
                self.count += 1
            
