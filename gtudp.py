'''
	GTUDP  --  Guaranteed Transmission User Datagram protocol

	How it works

	When you send a packet, GTUDP takes a hash of it, wraps it in a frame, then sends it to its destination.
	It will then wait for an RECV packet containing the sent packet's hash from the address it sent to.
	When it receives the RECV packet, it will send a ACK packet with the hash, and the transaction is complete.

	If the packet is sent and no RECV is received within [recv_time] seconds, the packet is transmitted again (with a new hash).
	If the recipient sends a RECV packet, but does not receive an ACK packet in [ack_time] seconds, the RECV packet is retransmitted.

	Terms:
		RECV -- a packet sent from recipient to sender notifying that a packet was received.
		ACK  -- a packet sent from sender to recipient notifying that a RECV packet was received.

	GTUDP Frame -- Packet Type: 0x1d 0xce

BYTE 0        1        2        3
	+--------+--------+--------+--------+
0	|        GTUDP MAGIC NUMBER         |
	+--------+--------+--------+--------+
4	|GTUDP MAGIC NUMBE|   PACKET TYPE   |
	+--------+--------+--------+--------+
8	|        PACKET IDENTITY HASH       |
	+--------+--------+--------+--------+
16	|               DATA                |
	|       ...    ......     ...       |
	+--------+--------+--------+--------+

	GTUDP RECV Packet -- Packet Type: 0x5f 0x30

BYTE 0        1        2        3
	+--------+--------+--------+--------+
0	|        GTUDP MAGIC NUMBER         |
	+--------+--------+--------+--------+
4	|GTUDP MAGIC NUMBE|   PACKET TYPE   |
	+--------+--------+--------+--------+
8	|        PACKET IDENTITY HASH       |
	+--------+--------+--------+--------+

	GTUDP ACK Packet -- Packet Type: 0xae 0xd5
	(Same as RECV packet, but with different packet type)

The GTUDP Magic Number is 0x00 0x00 0x66 0xfc 0x33 0x45

A result of this is that all GTUDP packets must start with one of:
	0x00 0x00 0x66 0xfc 0x33 0x45    0x1d 0xce
	0x00 0x00 0x66 0xfc 0x33 0x45    0x5f 0x30
	0x00 0x00 0x66 0xfc 0x33 0x45    0xae 0xd5
Followed by a 4 byte hash.


GTUDP Frame

BYTE 0        1        2        3        5
	+--------+--------+--------+--------+--------+
	|  TYPE  |        PACKET IDENTITY HASH       |
	+--------+--------+--------+--------+--------+
	|                    DATA                    |
	|                                            |
	+--------+--------+--------+--------+--------+

'''

from __future__ import print_function

import socket, threading, select, zlib, struct, binascii

try:
	import queue
except ImportError:
	import Queue as queue

import random, time # kek

class GTUDP:

	def __init__(self, sock, debug=False, magic_numbers=b''):

		self.magic_numbers = magic_numbers
		self.FRAME_IDENTIFIER = b'F'
		self.RECV_IDENTIFIER = b'R'
		self.ACK_IDENTIFIER = b'A'

		self.hexify = lambda x:binascii.hexlify(x).decode()

		if debug:

			class _DEBUGSOCKET:

				def __init__(self, sock, gtudp):
					self.sock = sock
					self.gtudp = gtudp
					self.hexify = gtudp.hexify
					self.substitutes = {
						gtudp.FRAME_IDENTIFIER: b'FRAME',
						gtudp.RECV_IDENTIFIER:  b'RECV ',
						gtudp.ACK_IDENTIFIER:   b'ACK  '
					}

				def sendto(self, data, addr):
					mn_len = len(self.gtudp.magic_numbers)
					ident_len = len(self.gtudp.RECV_IDENTIFIER)

					packet_type = self.substitutes[
						data[ mn_len : mn_len + ident_len ]
					] or b'!?!! '

					print('OUT',
						packet_type.decode(),
						self.hexify(data[mn_len + ident_len:mn_len + ident_len + 4]),
						data[mn_len + ident_len + 4:].decode('utf-8', 'replace')
					)
					return self.sock.sendto(data, addr)

				def recvfrom(self, length):
					mn_len = len(self.gtudp.magic_numbers)
					ident_len = len(self.gtudp.RECV_IDENTIFIER)

					data, addr = self.sock.recvfrom(length)
					packet_type = self.substitutes[data[mn_len:mn_len + ident_len]] or b'!?!! '
					print('IN ',
						packet_type.decode(),
						self.hexify(data[mn_len + ident_len:mn_len + ident_len + 4]),
						data[mn_len + ident_len + 4:].decode('utf-8', 'replace')
					)
					return data, addr

			self.socket = _DEBUGSOCKET(sock, self)
			self._socket = sock
		else:
			self._socket = sock
			self.socket = sock

		self.sent_packets = {}
		self.recv_queue = queue.Queue()
		self.received_packets = {} # {'identity hash': (RECV packet, peer address)}

		self.frame_count = 0

		self.running = False


	def start(self):
		self.thread = threading.Thread(target=self.run)
		self.running = True
		self.thread.start()


	def run(self):
		mn_len = len(self.magic_numbers)
		ident_len = len(self.FRAME_IDENTIFIER)

		while self.running or len(self.sent_packets) or len(self.received_packets):
			rlist = select.select([self._socket], [], [], 0.25)[0]

			if len(rlist) == 0:

				# resend packets in sent_packets
				for identity_hash in self.sent_packets:
					self.socket.sendto( *self.sent_packets[identity_hash] )

				# resend RECVs in received_packets
				for identity_hash in self.received_packets:
					self.socket.sendto( *self.received_packets[identity_hash] )

				continue

			data, addr = self.socket.recvfrom(65535)

			if not data[:mn_len] == self.magic_numbers:
				continue

			if data[mn_len:mn_len+ident_len] == self.FRAME_IDENTIFIER:                # DATA packet
				identity_hash = data[mn_len+ident_len:mn_len+ident_len+4]

				# we have received the same data packet twice - retransmit RECV packet immediately
				if identity_hash in self.received_packets:
					if not self.received_packets[identity_hash][1] == addr: # foul play!
						continue

					self.socket.sendto(self.received_packets[identity_hash][0], addr)

				# construct and store our RECV packet
				recv_packet = self.constructRecv(identity_hash)
				self.received_packets[identity_hash] = ( recv_packet, addr )

				# send our RECV packet
				self.socket.sendto(recv_packet, addr)

				# queue the data in the packet to be given to the user
				self.recv_queue.put( (data[mn_len+ident_len+4:], addr) )


			elif data[mn_len:mn_len+ident_len] == self.RECV_IDENTIFIER:               # RECV packet
				# time to send an ACK packet

				identity_hash = data[mn_len+ident_len:mn_len+ident_len+4]

				if not identity_hash in self.sent_packets:
					# received RECV packet for something we never sent?

					# TODO hotfix: just send an ACK packet anyway
					ack_packet = self.constructAck(identity_hash)
					self.socket.sendto(ack_packet, addr)

					continue

				ack_packet = self.constructAck(identity_hash)
				self.socket.sendto(ack_packet, addr)

				# TODO SCHEDULE THIS LATER ?
				del self.sent_packets[identity_hash]

			elif data[mn_len:mn_len+ident_len] == self.ACK_IDENTIFIER:                 # ACK packet
				# stop sending recv packets

				identity_hash = data[mn_len+ident_len:mn_len+ident_len+4]

				if not identity_hash in self.received_packets:
					continue

				del self.received_packets[identity_hash]



	def constructFrame(self, data):
		self.frame_count += 1
		identity_hash = struct.pack('!i', zlib.adler32(data) + self.frame_count)

		return (self.magic_numbers + self.FRAME_IDENTIFIER + identity_hash, identity_hash)


	def constructRecv(self, identity_hash):
		return self.magic_numbers + self.RECV_IDENTIFIER + identity_hash


	def constructAck(self, identity_hash):
		return self.magic_numbers + self.ACK_IDENTIFIER + identity_hash


	def sendto(self, data, addr):
		frame, identity_hash = self.constructFrame(data)
		packet = frame + data
		self.sent_packets[identity_hash] = (packet, addr)

		return self.socket.sendto(packet, addr)

	def recvfrom(self):
		return self.recv_queue.get()


	def cleanup(self):
		# start clearing the queue of sent_packets and received_packets
		# so we can join our thread and close our socket
		self.running = False
		self.thread.join()


if __name__ == '__main__':
	import sys, socket

	if sys.argv[1] == 'server':
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind(('localhost', 4323))

		udp = GTUDP(sock, debug=True)
		udp.start()

		for i in range(6):
			data, addr = udp.recvfrom()
			udp.sendto(b'ok, thanks!', addr)

		udp.cleanup()
		sock.close()

	elif sys.argv[1] == 'client':
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		host = ('localhost', 4323)

		udp = GTUDP(sock, debug=True)
		udp.start()

		for i in range(6):
			udp.sendto(b'yay ' + str(time.ctime()).encode(), host)
			data, addr = udp.recvfrom()

		udp.cleanup()
		sock.close()

	else:
		print('usage:',sys.argv[0],'[server|client]')
