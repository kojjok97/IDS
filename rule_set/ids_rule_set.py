import os 


def open_rule():             # rule파일을 열어 한줄씩 읽는 함수 (rule파일이 없다면 새로 만든다)
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
                
                

        
def read_rule():            # ruleOpen함수에서 rule파일을 읽어서 변수로 저장하는 함수


    if 'switch' in globals():

        return 

    rules = open_rule()
    if len(rules) == 0:
        return
    
    for rule in rules:
        rule = rule.split()
        if rule[0] not in globals():

            globals()[rule[0]] = []
            globals()[rule[0]].append([rule[1],rule[2]])
                
        else:
            globals()[rule[0]].append([rule[1],rule[2]])
    
    globals()['switch'] = 1


def check_rule(port,srcIp,dstIp):    # 받은 패킷의 Port, Source IP, Destination IP가 rule에 일치하는지 확인하는 함수
        
    
    if str(port) in globals():
        for src,dst in globals()[str(port)]:
            if srcIp == src and dstIp == dst:

                return True
            else :
                return False
    else :
        
        return False


