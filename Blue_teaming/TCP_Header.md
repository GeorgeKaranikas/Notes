
```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

###   Source Port :  16 bits

Tcp source Port can be of maximum 65.535
A pair of internet address and a port makes a socket.

###   Destination Port :  16 bits

Same for Destination port

###  Sequence Number :  32 bits

The sequence number of the first data octet in this segment (except
when SYN is present). If SYN is present the sequence number is the
initial sequence number (ISN) and the first data octet is ISN+1.

###   AcknowledgmentUrgent Pointer:  16 bits Number :  32 bits

If the ACK control bit is set this field contains the value of the
next sequence number the sender of the segment is expecting to
receive.  Once a connection is established this is always sent.

###   Data Offset :  4 bits

The length of TCP header in 32 bit words (dwords = 4bytes) and the offset of the start of the header that tcp data beggins.

###  Reserved :  6 bits

Always 0 as it is also calculated in checksums.

###   Control Bits:  6 bits

URG:  Urgent Pointer field significant
ACK:  Acknowledgment field significant
PSH:  Push Function
RST:  Reset the connection
SYN:  Synchronize sequence numbers
FIN:  No more data from sender

### Window : 16 bits

The number of data octets beginning with the one indicated in the acknowledgment field which the 
sender of this segment is willing to accept.

###   Checksum :  16 bits


The checksum field is the 16 bit one's complement of the one's
complement sum of all 16 bit words in the header and text.  If a
segment contains an odd number of header and text octets to be
checksummed, the last octet is padded on the right with zeros.
While computing the checksum, the checksum field itself is replaced with zeros.

! The checksum also covers a 96 bit pseudo header prefixed to tcp header.

### Urgent Pointer : 16 bits

to be used if the URG bit is set.
a positive offset from the sequence number in this segment
The urgent pointer points to the sequence number of the octet following the urgent data

### Options : variable length

multiple of a byte

###   Padding:  variable length

always padding with 0x00 bytes to ensure the header is a 32bit word multiple.

