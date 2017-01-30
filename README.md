# gtUDP
UDP socket wrapper that guarantees datagram delivery in Python

## How it works
When you send some data using gtUDP, it gets given a header, and is sent on it's merry way. This packet will be sent periodically until a RECV packet is received. When a RECV is received, an ACK is sent.

When you received a packet using gtUDP, it transmits an RECV packet. This packet will be sent periodically until an ACK packet is received.

### Usage

```
import socket
from gtudp import GTUDP

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(('localhost', 4323))


gtudp = GTUDP(server, debug=True)
gtudp.start()

for i in range(10):
	data, addr = gtudp.recvfrom(128)
	gtudp.sendto(data, addr)


# cleanup and close socket like normal
udp.cleanup()
server.close()

```
### TODO

 - Allow for packet exchanges to stop prematurely, if they run too long.
 - Correctly implement accepting/sending packets from non-gtUDP sources.
 - Implement a blocking variant of `sendto()` to return if transmission was successful.

### The inner workings

Default DATA packet

```
BYTE 0        1        2        3        4
    +--------+--------+--------+--------+--------+
0   |  TYPE  |        PACKET IDENTITY HASH       |
    +--------+--------+--------+--------+--------+
5   |                    DATA                    |
    |                                            |
    +--------+--------+--------+--------+--------+
```
Default RECV & ACK packets

```
BYTE 0        1        2        3        5
    +--------+--------+--------+--------+--------+
0   |  TYPE  |        PACKET IDENTITY HASH       |
    +--------+--------+--------+--------+--------+
```

Default Packet Type Bytes (aka Packet Identifier Bytes) are `0x1D` (DATA), `0x5F` (RECV), `0xAE` (ACK).  
These values can be changed to anything, with any length, but they must be changed at both ends, and all three MUST have the same length.

There is also an OPTIONAL magic number setting. By default it is off. The magic number is a sequence of bytes added to the start of all headers, and can have any length. If you wanted to have a 6 byte magic number, and 2 byte TYPEs, your packets would look like this:

```
BYTE 0        1        2        3
    +--------+--------+--------+--------+
0   |        GTUDP MAGIC NUMBER         |
    +--------+--------+--------+--------+
4   |GTUDP MAGIC NUMBE|   PACKET TYPE   |
    +--------+--------+--------+--------+
8   |        PACKET IDENTITY HASH       |
    +--------+--------+--------+--------+
16  |               DATA                |
    |                                   |
    +--------+--------+--------+--------+
```
