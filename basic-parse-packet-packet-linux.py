import struct
import sys
import socket
import codecs

def ethernet_head(raw_data):
 dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
 
 #hex_mac_dest = codecs.encode(dest, 'hex')
 #mac_dest=hex_mac_dest.decode('utf-8') #decodifica byte
 
 hex_mac_src = codecs.encode(src, 'hex')
 mac_src = hex_mac_src.decode('utf-8')
 
 protocol = protocol_verify(prototype)
 
 print('\n>Ethernet Frame:')
 #print('>...Destination:',':'.join(mac_dest[i:i+2] for i in range(0,12,2))) # exibe o mac formatado
 print('>...Destination:', show_mac(dest)) # exibe o mac formatado
 print('>...Source:     ',show_mac(src))
 print('>...Protocol:     {}({})'.format(protocol[0], protocol[1]))
 return protocol

def protocol_verify(prototype):#retorna o tipo de protocolo
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
    
    
def ip_head(protocol, data):
     
    if(protocol[1] == 'ARP'):
        ARP_packet(data)
        
    
def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     protocol = ethernet_head(raw_data)
     ip_head(protocol, raw_data)
     
     print('===========================================================================')
     print('===========================================================================')
     
     
     

main()
