import struct
import sys
import socket
import getmac

def ethernet_head(raw_data):
 dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
 dest_mac = getmac.get_mac_addr(dest)
 src_mac = getmac.get_mac_addr(src)
 proto = socket.htons(prototype)
 data = raw_data[14:]
 return dest_mac, src_mac, proto, data 

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     eth = ethernet_head(raw_data)
     print('\nEthernet Frame:')
     print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],
    eth[2]))
main()
