import socket

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
     raw_data, addr = s.recvfrom(65535)
     eth = ethernet(raw_data)
     print('\nEthernet Frame:')
     print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1],
    eth[2]))
main()
