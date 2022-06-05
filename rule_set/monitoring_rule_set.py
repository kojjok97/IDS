import re


def inspect_protocol(protocol): # 입력받은 인자가 정확하게 입력되었는지 확인하는 함수
    if protocol == 'tcp':
        return
    elif protocol == 'icmp':
        return
    elif protocol == 'udp':
        return 
    elif protocol == 'arp':
        return
    elif protocol == 'any':
        return
    else:
        raise Exception('Try to insert right protocol')
 
        
def check_argument(parse_arguments):      # 인자에서 받은 Interface, Port, Ip를 순서대로 배열에 저장해서 반환하는 함수
    checkArray = []
    if parse_arguments['protocol'] == 'any':
        
        for i in parse_arguments:
            
            if parse_arguments[i] == None or i == 'mode' :
                is_ip(checkArray[3],checkArray[4])
                return checkArray
            else :
                checkArray.append(parse_arguments[i])      
                   


    elif parse_arguments['protocol'] == 'tcp' or parse_arguments['protocol'] == 'udp':
            
            

        for i in parse_arguments:
            
            if parse_arguments[i] == None or i == 'mode' :
                is_ip(checkArray[3],checkArray[4])
                return checkArray
            else :
                checkArray.append(parse_arguments[i])      
                   
    else:
        if parse_arguments['sport'] != 0 or parse_arguments['dport'] != 0:
            raise Exception('{} needs not to specify the port number'.format(parse_arguments['protocol']))
        else:
            for i in parse_arguments:
                if parse_arguments[i] != None:
                    checkArray.append(parse_arguments[i]) 
            is_ip(checkArray[3],checkArray[4])
            return checkArray

        

        
def is_ip(src_ip,dst_ip):        # 인자에서 받은 IP가 정확하게 IP형식으로 입력되었는지 확인하는 함수 IP형식으로 입력되지 않았다면 에러 반환 후 종료
    ipCheck = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[.]){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
    anyCheck = re.compile('^any$')
    srcIp = ipCheck.search(src_ip)        
    dstIp = ipCheck.search(dst_ip)
    srcAny = anyCheck.search(src_ip)
    dstAny = anyCheck.search(dst_ip)
    if srcIp == None:
        if srcAny == None:
            raise Exception('Try to insert right IP adress')
            
    if dstIp == None:
        if dstAny == None:
            raise Exception('Try to insert right IP adress')


def compare_arguments(port_ip,packet_array):  # 인자에서 받은 port,ip가 패킷의 port와 ip와 일치하는지 확인하는 함수
    
    count = 0
    
    for i in range(len(packet_array)):
        
        if 'any' == port_ip[i] or port_ip[i] == 0:
            count += 1
            continue
        elif port_ip[i] == packet_array[i]:
            count += 1
            continue
        else:
            break
    if count == len(packet_array):
        
        return True
    else:
        
        return False


