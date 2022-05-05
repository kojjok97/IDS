import os 
import re

def inspectProtocol(protocol):
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



def ruleOpen():
    rules = []
    
    if 'rule' not in os.listdir('./') :
        with open ('./rule','w') as f :
            f.write('')

    with open('./rule','r') as f:
        while True:
            line = f.readline()
            if not line : break 
            rules.append(line[:-1])
    return rules
                
                

        
def readRule():


    if 'switch' in globals():

        return 

    rules = ruleOpen()
    if len(rules) == 0:
        return
    
    for rule in rules:
        rule = rule.split()
        if rule[0] not in globals():

            globals()[rule[0]] = []
            globals()[rule[0]].append([rule[1],rule[2]])
                
        else:
            globals()[rule[0]] = []
            globals()[rule[0]].append([rule[1],rule[2]])
    
    globals()['switch'] = 1
    


def checkRule(port,srcIp,dstIp):
        
    
    if str(port) in globals():
        for src,dst in globals()[str(port)]:
            if srcIp == src and dstIp == dst:

                return True
            else :
                return False
    else :
        
        return False
        
        
def checkArgument(parseArguments):
    checkArray = []
    if parseArguments['protocol'] == 'any':
        
        for i in parseArguments:
            
            if parseArguments[i] == None or i == 'mode' :
                isIp(checkArray[3],checkArray[4])
                return checkArray
            else :
                checkArray.append(parseArguments[i])      
                   


    elif parseArguments['protocol'] == 'tcp' or parseArguments['protocol'] == 'udp':
            
            

        for i in parseArguments:
            
            if parseArguments[i] == None or i == 'mode' :
                isIp(checkArray[3],checkArray[4])
                return checkArray
            else :
                checkArray.append(parseArguments[i])      
                   
    else:
        if parseArguments['sport'] != 0 or parseArguments['dport'] != 0:
            raise Exception('{} needs not to specify the port number'.format(parseArguments['protocol']))
        else:
            for i in parseArguments:
                if parseArguments[i] != None:
                    checkArray.append(parseArguments[i]) 
            isIp(checkArray[3],checkArray[4])
            return checkArray

        

        
def isIp(src_ip,dst_ip):
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


def compareArguments(port_ip,packetArray):
    
    count = 0
    
    for i in range(len(packetArray)):
        
        if 'any' == port_ip[i] or port_ip[i] == 0:
            count += 1
            continue
        elif port_ip[i] == packetArray[i]:
            count += 1
            continue
        else:
            break
    if count == len(packetArray):
        
        return True
    else:
        
        return False


