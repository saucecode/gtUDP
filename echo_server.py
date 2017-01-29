'''
        A simple echo server
		Waits for data from anyone, then echoes it back.

		Debug messages are on in this example.
'''

from __future__ import print_function

import socket

from gtudp import GTUDP

# create your socket like normal
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('localhost', 4323))

# wrap it, start the thread
udp = GTUDP(server, debug=True)
udp.start()

# do your networking like normal!
data, addr = udp.recvfrom()
udp.sendto(data, addr)

# cleanup must be called -- THIS WILL BLOCK
udp.cleanup()

# close your socket like normal when you're done with it
server.close()
