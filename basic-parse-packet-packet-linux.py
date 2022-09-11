import struct
import sys
import socket
import codecs

global packets_percent

def ethernet_head(raw_data):
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
    
def raw_to_string(raw_info):# return input -> hex -> utf-8 -> string
    hex_info = codecs.encode(raw_info, 'hex')
    str_rtn = hex_info.decode('utf-8')
    return str_rtn
def ip_protocol_verify(n_protocol):
    protocol_hex = hex(n_protocol)
    protocol_name='none'
    
    if(n_protocol == 1): protocol_name = 'ICMP'
    if(n_protocol == 6): protocol_name = 'TCP'
    if(n_protocol == 17): protocol_name = 'UDP'  
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
    flags = parse_packet[6]
     
    flags = ((flags >> 7), (flags >> 6), (flags >> 5))
    
    
    
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
    
    return ip_protocol_verify(proto), data
    

def ipv6_header(data):
    
    parse_packet = data[14:] #para identificacao dos cabelhos do IP, ficara mais facil apos o parse a contagem comeca em 0
    
    version_header_length = parse_packet[0]
    version = version_header_length >> 4
    
    
def ip_head(protocol, data):
    if(protocol[1] == 'none'):
        print("Failed to parse ProtocolType")
    elif(protocol[1] == 'ARP'):
        ARP_packet(data)
    elif(protocol[1] == 'IPv4'):
        protocol, data = ipv4_header(data)
        return protocol, data
    elif(protocol[1] == 'IPv6'):
        ipv6_header(data)
    else:
        return
        
        
        
        
    
def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     encapsulated_protocol_ethernet = ethernet_head(raw_data)
     encapsulated_protocol_ip = ip_head(encapsulated_protocol_ethernet, raw_data)
     
     
     print('===========================================================================')
     print('===========================================================================')
     
     
     

main()
