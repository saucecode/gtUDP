'''
        A simple echo client.
        Takes one input from the user and sends it to a server.
        Then waits for a reply from the server.

        Debug messages are on in this example.
'''

from __future__ import print_function

import socket, time

from gtudp import GTUDP

# create your socket like normal
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host = ('localhost', 4323)

# wrap it and start the thread
udp = GTUDP(sock, debug=True)
udp.start()

# write your network code like normal!

try:
	message = raw_input('enter message: ')
except:
	message = input('enter message: ')


udp.sendto(message.encode(), host)
data, addr = udp.recvfrom()

print(addr, 'says:', data.decode())

udp.cleanup()
sock.close()
