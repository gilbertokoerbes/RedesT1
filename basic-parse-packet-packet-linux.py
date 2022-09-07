import struct
import sys
import socket
import codecs

def ethernet_head(raw_data):
 dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
 
 hex_mac_dest = codecs.encode(dest, 'hex')
 mac_dest=hex_mac_dest.decode('utf-8') #decodifica byte
 
 hex_mac_src = codecs.encode(src, 'hex')
 mac_src = hex_mac_src.decode('utf-8')
 
 protocol = protocol_verify(prototype)
 data = raw_data[14:]
 print('\n> Ethernet Frame:')
 print('>...Destination:',':'.join(mac_dest[i:i+2] for i in range(0,12,2))) # exibe o mac formatado
 print('>...Source:     ',':'.join(mac_src[i:i+2] for i in range(0,12,2)))
 print('>...Protocol:     {}({})'.format(protocol[0], protocol[1]))
 return protocol, data

def protocol_verify(prototype):#retorna o tipo de protocolo
    protocol_hex = hex(prototype)
    protocol_name='none'
    
    if(prototype == 2048): protocol_name = 'IPv4'
    if(prototype == 34525): protocol_name = 'IPv6'
    if(prototype == 2054): protocol_name = 'ARP'  
    return protocol_hex, protocol_name
    
def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     protocol, data = ethernet_head(raw_data)
     

main()
