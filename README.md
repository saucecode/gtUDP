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

udp = GTUDP(server, debug=True)
udp.start()

data, addr = udp.recvfrom(128)
udp.sendto(data, addr)

udp.cleanup()
server.close()

```

### The inner workings

DATA packet

```
BYTE 0        1        2        3        4
    +--------+--------+--------+--------+--------+
0   |  TYPE  |        PACKET IDENTITY HASH       |
    +--------+--------+--------+--------+--------+
5   |                    DATA                    |
    |                                            |
    +--------+--------+--------+--------+--------+
```
RECV & ACK packets

```
BYTE 0        1        2        3        5
    +--------+--------+--------+--------+--------+
0   |  TYPE  |        PACKET IDENTITY HASH       |
    +--------+--------+--------+--------+--------+
```

Packet Type Bytes are `0x1D` (DATA), `0x5F` (RECV), `0xAE` (ACK).  
These values can be changed to anything, but they must be changed at both ends, and all three MUST have the same length.

There is also an OPTIONAL magic number setting. By default it is off. Magic numbers is a sequence of bytes added to the start of the header, and can have any length. If you wanted to have a 6 byte magic number, and 2 byte TYPEs, your packets would look like this:

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
