from __future__ import print_function

import socket, threading, select, zlib, struct, binascii

try:
	import queue
except ImportError:
	import Queue as queue

import random, time # kek

class GTUDP:

	def __init__(self, sock, debug=False, magic_numbers=b'', recv_from_any=False):

		self.magic_numbers = magic_numbers
		self.FRAME_IDENTIFIER = b'\x1d'
		self.RECV_IDENTIFIER = b'\x5f'
		self.ACK_IDENTIFIER = b'\xae'

		self.data_attempts = 6 # number of times to retransmit DATA packets
		self.recv_attempts = 10 # number of times to retransmit RECV packets

		if not len(self.FRAME_IDENTIFIER) == len(self.RECV_IDENTIFIER) == len(self.ACK_IDENTIFIER):
			raise ValueError('Identifier bytes are different lengths!')

		self.identifiers = (self.FRAME_IDENTIFIER, self.RECV_IDENTIFIER, self.ACK_IDENTIFIER)

		self.recv_from_any = recv_from_any

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

					packet_type = self.substitutes.get(data[mn_len:mn_len + ident_len], b'!?!! ')

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

					packet_type = self.substitutes.get(data[mn_len:mn_len + ident_len], b'!?!! ')
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

		self.frame_count = random.getrandbits(32)

		self.running = False

		self.blocking = True
		self.recv_timeout = None


	def start(self):
		self.thread = threading.Thread(target=self.run)
		self.running = True
		self.thread.start()


	def run(self):
		mn_len = len(self.magic_numbers)
		ident_len = len(self.FRAME_IDENTIFIER)

		while self.running or len(self.sent_packets) or len(self.received_packets):
			rlist = select.select([self._socket], [], [], 0.5)[0]

			if len(rlist) == 0:

				# resend packets in sent_packets
				for identity_hash in self.sent_packets:
					self.socket.sendto( *self.sent_packets[identity_hash]['packet'] )
					self.sent_packets[identity_hash]['sent'] += 1

				self.sent_packets = { k:v for k,v in self.sent_packets.items() if v['sent'] < self.data_attempts }

				# resend RECVs in received_packets
				for identity_hash in self.received_packets:
					self.socket.sendto( *self.received_packets[identity_hash]['packet'] )
					self.received_packets[identity_hash]['sent'] += 1


				self.received_packets = { k:v for k,v in self.received_packets.items() if v['sent'] < self.recv_attempts }

				continue

			data, addr = self.socket.recvfrom(65535)

			if not data[:mn_len] == self.magic_numbers:
				if self.recv_from_any:
					self.recv_queue.put( (data,addr) )
				continue

			if data[mn_len:mn_len+ident_len] == self.FRAME_IDENTIFIER:                # DATA packet
				identity_hash = data[mn_len+ident_len:mn_len+ident_len+4]
				is_repeated_packet = identity_hash in self.recieved_history
				# we have received the same data packet twice - retransmit RECV packet immediately
				if identity_hash in self.received_packets:
					if not self.received_packets[identity_hash]['packet'][1] == addr: # foul play!
						continue

					self.socket.sendto(self.received_packets[identity_hash]['packet'][0], addr)

				# queue the data in the packet to be given to the user
				if not identity_hash in self.received_packets:
					self.recv_queue.put( (data[mn_len+ident_len+4:], addr) )

				# construct and store our RECV packet
				recv_packet = self.constructRecv(identity_hash)
				self.received_packets[identity_hash] = {'packet':( recv_packet, addr ), 'sent':1}

				# send our RECV packet
				self.socket.sendto(recv_packet, addr)


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


			elif self.recv_from_any:
				self.recv_queue.put( (data,addr) )



	def constructFrame(self, data):
		self.frame_count += 1
		identity_hash = struct.pack('!I', (zlib.adler32(data) + self.frame_count) & 0xffffffff)

		return (self.magic_numbers + self.FRAME_IDENTIFIER + identity_hash, identity_hash)


	def constructRecv(self, identity_hash):
		return self.magic_numbers + self.RECV_IDENTIFIER + identity_hash


	def constructAck(self, identity_hash):
		return self.magic_numbers + self.ACK_IDENTIFIER + identity_hash

	def isValidPacket(self, packet):
		mn_len = len(self.magic_numbers)
		ident_len = len(self.FRAME_IDENTIFIER)
		return all([
			packet[:mn_len] == self.magic_numbers,
			packet[mn_len:mn_len+ident_len] in self.identifiers
		])

	def sendto(self, data, addr):
		frame, identity_hash = self.constructFrame(data)
		packet = frame + data
		self.sent_packets[identity_hash] = {'packet':(packet, addr), 'sent':1}

		return self.socket.sendto(packet, addr)

	def recvfrom(self, length=None):
		if length:
			data, addr = self.recv_queue.get(self.blocking, self.recv_timeout)
			return (data[:length], addr)
		else:
			return self.recv_queue.get(self.blocking, self.recv_timeout)

	def cleanup(self):
		# start clearing the queue of sent_packets and received_packets
		# so we can join our thread and close our socket
		self.running = False
		self.thread.join()

	def settimeout(self, seconds):
		self.recv_timeout = seconds

	def setblocking(self, should_block):
		self.blocking = should_block


if __name__ == '__main__':
	import sys, socket

	if sys.argv[1] == 'server':
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.bind(('0.0.0.0', 4323))

		udp = GTUDP(sock, debug=True)
		udp.start()

		for i in range(3):
			data, addr = udp.recvfrom()
			udp.sendto(data + b' thanks', addr)

		udp.cleanup()
		sock.close()

	elif sys.argv[1] == 'client':
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		host = (sys.argv[2], 4323)
		#sock.connect(host)

		udp = GTUDP(sock, debug=True)
		udp.start()

		for i in range(3):
			time.sleep(2)
			udp.sendto(b'yay ' + str(time.ctime()).encode(), host)
			data, addr = udp.recvfrom()

		print('attempting to stop...')
		udp.cleanup()
		sock.close()

	else:
		print('usage:',sys.argv[0],'[server|client]')
