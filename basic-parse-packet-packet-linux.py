
import struct
import sys
import socket
import codecs

global packets_percent 
packets_percent = {'Ethernet': 0, 'Arp': 0, 'Ipv4': 0, 'Ipv6': 0, 'Icmp': 0, 'Icmpv6': 0, 'Udp': 0, 'Tcp': 0, 'Dns': 0}
global total
total = 0

def ethernet_head(raw_data):
    #ETHENET ++
 dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
 
 #hex_mac_dest = codecs.encode(dest, 'hex')
 #mac_dest=hex_mac_dest.decode('utf-8') #decodifica byte
 
 #hex_mac_src = codecs.encode(src, 'hex')
 #mac_src = hex_mac_src.decode('utf-8')
 
 protocol = ethernet_protocol_verify(prototype)
 
 print('\n>ETHERNET FRAME:')
 #print('>...Destination:',':'.join(mac_dest[i:i+2] for i in range(0,12,2))) # exibe o mac formatado
 print('>...Destination:', show_mac(dest)) # exibe o mac formatado
 print('>...Source:     ',show_mac(src))
 print('>...Protocol:     {}({})'.format(protocol[0], protocol[1]))
 packets_percent['Ethernet'] += 1
 return protocol

def ethernet_protocol_verify(prototype):#retorna o tipo de protocolo
    protocol_hex = hex(prototype)
    protocol_name='none'
    
    if(prototype == 2048): protocol_name = 'IPv4'
    if(prototype == 34525): protocol_name = 'IPv6'
    if(prototype == 2054): protocol_name = 'ARP'  
    return protocol_hex, protocol_name

def show_mac(hex_mac): #retorna mac formatado
    
    hex_mac = codecs.encode(hex_mac, 'hex')
    mac_utf= hex_mac.decode('utf-8') #decodifica byte
    mac_output = ':'.join(mac_utf[i:i+2] for i in range(0,12,2))
    return mac_output
    
    
def show_ip(hex_ip): #recebe o IP em hexa e retorna em IP formatado
    
    ip_output=''
    for x in range (len(hex_ip)):
        ip_hex = codecs.encode(hex_ip[x:x+1], 'hex')
        ip_output = ip_output + str((int(ip_hex, base=16))) + '.'
        
    ip_output = ip_output[0:len(ip_output)-1] #remover ultimo ponto
    return ip_output
    

def ARP_packet(packet):
    #print(packet[21:])
    opcode, sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! H 6s 4s 6s 4s', packet[20:42])
    print('>> ARP:')
    print('>>...opcode: request({})'.format(opcode)) if opcode==1 else print('>>...opcode: reply({})'.format(opcode))
    print ('>>...sender mac', show_mac(sender_mac))
    print ('>>...sender ip', show_ip(sender_ip))
    print ('>>...target mac', show_mac(target_mac))
    print ('>>...target ip', show_ip(target_ip))
    packets_percent['Arp'] += 1
    
def raw_to_string(raw_info):# return transform input -> hex -> utf-8 -> string
    hex_info = codecs.encode(raw_info, 'hex')
    str_rtn = hex_info.decode('utf-8')
    return str_rtn
def ip_protocol_verify(n_protocol):
    protocol_hex = hex(n_protocol)
    protocol_name='none'
    
    if(n_protocol == 1): protocol_name = 'ICMP'
    if(n_protocol == 6): protocol_name = 'TCP'
    if(n_protocol == 17): protocol_name = 'UDP'  
    if (n_protocol == 58): protocol_name = 'ICMPv6'
    if (n_protocol == 59): protocol_name = 'No next Header'

    return protocol_hex, protocol_name
    
    
def ipv4_header(data):
    parse_packet = data[14:] #para identificacao dos cabelhos do IPv4, ficara mais facil apos o parse a contagem comeca em 0
    
    version_header_length = parse_packet[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    total_length = struct.unpack('! H', parse_packet[2:4]) #retorna uma tupla, com segundo valor vazio
    total_length = total_length[0]
    
    #ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', parse_packet[:20])
    identification_raw, flags_and_fragment = struct.unpack('! 2s 2s', parse_packet[4:8])
    identification = raw_to_string(identification_raw)
    #flags = parse_packet[6]
     
    #flags = ((flags >> 7), (flags >> 6), (flags >> 5))
    packets_percent['Ipv4'] += 1
    
    
    ttl, proto, src, target = struct.unpack('! B B 2x 4s 4s', parse_packet[8:20]) 
    
    print('>>INTERNET PROTOCOL VERSION 4')
    print('>>..Version', version)
    print('>>..Header Length', header_length)
    #print('DSCP and ECN:#####')
    print('>>..Total length', total_length)
    print('>>..Identification {} ({})'.format(identification, int(identification, base=16)))
    #print('Flags')
    #print('{} = Reserved bit'.format(flags[0]))
    #print(".{} = Don't fragment".format(flags[1]))
    #print("..{} = More fragments".format(flags[2]))
    print('>>..TTL = ', ttl)
    print('>>..Protocol = ', proto, ip_protocol_verify(proto))
    print('>>..Source IP = ', show_ip(src))
    print('>>..Destination IP = ', show_ip(target))
    protocol_rtn =ip_protocol_verify(proto)
    return protocol_rtn

    
    
def ipv6_header(data):
    parse_packet = data[14:] #para identificacao dos cabelhos do IPv4, ficara mais facil apos o parse a contagem comeca em 0
    ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack("!IHBB", parse_packet[0:8])
    ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, parse_packet[8:24])
    ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, parse_packet[24:40])

    bin(ipv6_first_word)
    "{0:b}".format(ipv6_first_word)
    version = ipv6_first_word >> 28
    traffic_class = ipv6_first_word >> 16
    traffic_class = int(traffic_class) & 4095
    flow_label = int(ipv6_first_word) & 65535

    #ipv6_next_header = nextHeader(ipv6_next_header)
    data = data[40:]
    print(">>INTERNET PROTOCOL VERSION 6")
    print(">>..Internet Protocol = ", version)
    print(">>..Traffic Class = ", traffic_class)
    print(">>..Flow Label = ", flow_label)
    print(">>..Payload lengh = ", ipv6_payload_legth)
    print(">>..Next Header= {}({})".format(ipv6_next_header, ip_protocol_verify(ipv6_next_header)))
    print(">>..Hop Limit = ", ipv6_hoplimit)
    print(">>..Source Address = ", ipv6_src_ip)
    print(">>..Destination Address = ", ipv6_dst_ip)
    
    
    
    packets_percent['Ipv6'] += 1
    return ip_protocol_verify(ipv6_next_header)
    '''parse_packet = data[14:] #para identificacao dos cabelhos do IP, ficara mais facil apos o parse a contagem comeca em 0
    version_header_length = parse_packet[0]
    version = version_header_length >> 4'''

    
    pass
    
    
def ip_head(protocol, data):
    if(protocol[1] == 'none'):
        print("Failed to parse ProtocolType")
    elif(protocol[1] == 'ARP'):
        ARP_packet(data)
        return 'none'
    elif(protocol[1] == 'IPv4'):
        encapsulated_protocol_ip = ipv4_header(data)
        return encapsulated_protocol_ip
    elif(protocol[1] == 'IPv6'):
        encapsulated_protocol_ip = ipv6_header(data)
        return encapsulated_protocol_ip
    else:
        return

def icmp_head(data):
    parse_packet = data[34:]
    type_icmp, code, checksum = struct.unpack('! B B 2s', parse_packet[0:4])
    
    print(">>>ICMP")
    if(type_icmp==0): print('>>>... Echo: reply({})'.format(type_icmp))
    elif(type_icmp==8): print('>>>... Echo: request({})'.format(type_icmp))
    elif(type_icmp==3): print('>>>... Destination Unreachable({})'.format(type_icmp))
    else: print('>>>... other type = ({})'.format(type_icmp))
    
    print(">>>... Code = ", code)
    print(">>>... Checksum = ", raw_to_string(checksum))
    packets_percent['Icmp'] += 1
    
def icmpv6_head(data):
    parse_packet = data[54:] #14 bytes ethernet + 40 bytes ipv6
    type_icmp, code, checksum = struct.unpack('! B B 2s', parse_packet[0:4])
    
    print(">>>ICMPv6")
    if(type_icmp==129): print('>>>... Echo: reply({})'.format(type_icmp))
    elif(type_icmp==128): print('>>>... Echo: request({})'.format(type_icmp))
    elif(type_icmp==1): print('>>>... Destination Unreachable({})'.format(type_icmp))
    else: print('>>>... other type = ({})'.format(type_icmp))
    
    print(">>>... Code = ", code)
    print(">>>... Checksum = ", raw_to_string(checksum))
    packets_percent['Icmpv6'] += 1
    


def search_port_protocol_application(source_port, destination_port): #procura no dicionario os protocolos conhecidos com base nas portas
    applications_ports = {53:'DNS', 80:'HTTP', 443:'HTTPS'}
    application_rtn=''
    if (source_port in applications_ports): application_rtn = applications_ports[source_port]
    elif (destination_port in applications_ports): application_rtn = applications_ports[destination_port]
    else: application_rtn='Application not detected'
    return application_rtn    

def tcp_head(data):
    packets_percent['Tcp'] += 1
    
    parse_packet = data[34:]
    source_port, destination_port= struct.unpack('! H H', parse_packet[0:4])
    application = search_port_protocol_application(source_port, destination_port)
    
    seq_number, ack_number = struct.unpack('! 4s 4s', parse_packet[4:12])
    window_tcp = struct.unpack('! H', parse_packet[14:16])
    checksum, urgent_pointer = struct.unpack('! H H', parse_packet[16:20])
    
    print(">>>TCP:")
    print(">>>... Source Port:", source_port)
    print(">>>... Destination Port:", destination_port)
    print(">>>... Sequence Number(raw):", int(raw_to_string(seq_number), base=16))
    print(">>>... Acknowledgement Number(raw):", int(raw_to_string(ack_number), base=16))
    print(">>>... Window:", window_tcp)
    print(">>>... Checksum:", checksum)
    print(">>>... Urgent Pointer:", urgent_pointer)
    print(">>>... Application:", application)
    
    return application
    
    
    pass
def udp_head(data):
    packets_percent['Udp'] += 1
    parse_packet = data[34:]
    source_port, destination_port, length, checksum = struct.unpack('! H H H 2s', parse_packet[0:8])
    application = search_port_protocol_application(source_port, destination_port)
    
    print(">>>UDP:")
    print(">>>... Source Port:", source_port)
    print(">>>... Destination Port:", destination_port)
    print(">>>... Length:", length)
    print(">>>... Checksum:", raw_to_string(checksum))
    print(">>>... Application:", application)
    
    return application
    
    pass

def tcp_ip_layer(encapsulated_protocol_ip, raw_data):
    
    if(encapsulated_protocol_ip[1] == 'none'):
        print("Failed to parse ProtocolType")
        
    elif(encapsulated_protocol_ip[1] == 'ICMP'):
        icmp_head(raw_data)
        
    elif(encapsulated_protocol_ip[1] == 'ICMPv6'):
        icmpv6_head(raw_data)
        
    elif(encapsulated_protocol_ip[1] == 'TCP'):
        protocol_application = tcp_head(raw_data)
        return protocol_application
    
    elif(encapsulated_protocol_ip[1] == 'UDP'):
        protocol_application = udp_head(raw_data)
        return protocol_application    
        
    else:
        return
        

#DNS
def application_protocol_head(application_protocol, data):
    
    if (application_protocol == 'DNS'): #DNS Header format 16 bit per line (2 bytes)
        packets_percent['Dns'] += 1
        parse_packet = data[42:]
        
        transaction_id= (struct.unpack('! 2s', parse_packet[0:2]))[0]


        flag_byte1,flag_byte2  = struct.unpack('! s s ', parse_packet[2:4])

        #print(flag_byte1)
        
        
        byte1_to_bit = str(bin(int(raw_to_string(flag_byte1), base=16))).lstrip('0b')
        #print(byte1_to_bit)
        while len(byte1_to_bit) <8: byte1_to_bit='0'+byte1_to_bit  #preenchimento de a esquerda   
        
        qr = byte1_to_bit[0]
        opcode = byte1_to_bit[1:4]
        aa = byte1_to_bit[5]
        tc = byte1_to_bit[6]
        rd = byte1_to_bit[7]
        
        byte2_to_bit = str(bin(int(raw_to_string(flag_byte2), base=16))).lstrip('0b')
        while len(byte2_to_bit) <8: byte2_to_bit='0'+byte2_to_bit #preenchimento de a esquerda        
        #print(byte2_to_bit)
        ra = byte2_to_bit[0]
        z = byte2_to_bit[1:4]
        rcode =  byte2_to_bit[4:8]
        

        print(">>>>>DOMAIN NAME SYSTEM")
        print(">>>>>.... Transaction ID = 0x{}".format(raw_to_string(transaction_id)))
        print(">>>>>....QR = {} Query".format(qr)) if qr == '0' else print(">>>>>....QR = {} Response".format(qr))
        print(">>>>>....Opcode = ", opcode)
        print(">>>>>.....AA = {} ( Authoritative Answer)".format(aa))
        print(">>>>>.......TC = {} ( TrunCation)".format(tc))
        print(">>>>>.........RD = {} ( Recursion Desired)".format(rd))
        print(">>>>>...........RA = {} ( Recursion Available)".format(ra))
        print(">>>>>...........Reserved = {} (Z)".format(z))
        print(">>>>>.....Response Code = {} ".format(rcode))
        
        
def calcula():
    arq = open('estatistica.txt', 'w')
    arq.write(f"Ethernet: {(packets_percent['Ethernet']/total)*100}%\n")
    
    arq.write(f"ARP: {(packets_percent['Arp']/total)*100}%\n")
    arq.write(f"IPv4: {(packets_percent['Ipv4']/total)*100}%\n")
    arq.write(f"IPv6: {(packets_percent['Ipv6']/total)*100}%\n")
    arq.write(f"ICMP: {(packets_percent['Icmp']/total)*100}%\n")
    arq.write(f"ICMPv6: {(packets_percent['Icmpv6']/total)*100}%\n")
    arq.write(f"UDP: {(packets_percent['Udp']/total)*100}%\n")
    arq.write(f"TCP: {(packets_percent['Tcp']/total)*100}%\n")
    arq.write(f"DNS: {(packets_percent['Dns']/total)*100}%\n")
    
    pass  
          
    
def main():
    global total
    total = 0
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     #PACOTE TOTAL
     total += 1
     
     encapsulated_protocol_ethernet = ethernet_head(raw_data)
     encapsulated_protocol_ip = ip_head(encapsulated_protocol_ethernet, raw_data)
     application_protocol = tcp_ip_layer(encapsulated_protocol_ip, raw_data)
     application_protocol_head(application_protocol, raw_data)
     
     #funcao calcula estatisticas
     calcula()
     #open (w )
     # % tipo =  tipo / totalpacotes * 100
    
     
     print('===========================================================================')
     print('===========================================================================')
     
     
     

main()
