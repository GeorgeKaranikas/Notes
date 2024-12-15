
# IPv4 Header

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```
### Version : 4 bits

its 0x04 here -> 100

### IHL (Internet Header Length) : 4 bits

bits are multiplied to 32 bit words (which is actually a dword , 4 bytes)
and valied values are  more than 5 and no more than 60

### TOS (Type of Service) :  8 bits

```
    0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+
```

a collection of parameters and switches , interpreted by routers and gateways,
in order for prioritization and quality of service to be applied , if present in gateways
capabilities.


      Bits 0-2:  Precedence.
      Bit    3:  0 = Normal Delay,      1 = Low Delay.
      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
      Bit  6-7:  Reserved for Future Use.

[More on precedence here](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)

###  Total Length :  16 bits

This is the total length of the IP segment (header and data),in bytes (unit here is an octet) , and can reach a maximum of 65,535 octets.
All hosts accept 576-byte datagrams and is recomended to send packets larger than this number

### Identification :  16 bits

Helps with identification fragmented packets and reassembling them

### Flags : 3 bits

Fragmentation Flags

Bit 0: reserved, must be zero
Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

### Fragmentation Offset : 13 bits


The fragment offset is measured in units of 8 octets (64 bits).  The
first fragment has offset zero.

### Time to Live :  8 bits

Could also called hops to leave.
After reaching a host or gateway it is decremented by one.
Uppon reaching 0 ,it is descarded.

###  Protocol :  8 bits


      Decimal    Octal      Protocol Numbers                  References
      -------    -----      ----------------                  ----------
           0       0         Reserved                              [JBP]
           1       1         ICMP                               [53,JBP]
           2       2         Unassigned                            [JBP]
           3       3         Gateway-to-Gateway              [48,49,VMS]
           4       4         CMCC Gateway Monitoring Message [18,19,DFP]
           5       5         ST                                 [20,JWF]
           6       6         TCP                                [34,JBP]
           7       7         UCL                                    [PK]
           8      10         Unassigned                            [JBP]
           9      11         Secure                                [VGC]
          10      12         BBN RCC Monitoring                    [VMS]
          11      13         NVP                                 [12,DC]
          12      14         PUP                                [4,EAT3]
          13      15         Pluribus                             [RDB2]
          14      16         Telenet                              [RDB2]
          15      17         XNET                              [25,JFH2]
          16      20         Chaos                                [MOON]
          17      21         UDP  (User Datagram)                      [42,JBP]
          18      22         Multiplexing                       [13,JBP]
          19      23         DCN                                  [DLM1]
          20      24         TAC Monitoring                     [55,RH6]
       21-62   25-76         Unassigned                            [JBP]
          63      77         any local network                     [JBP]
          64     100         SATNET and Backroom EXPAK            [DM11]
          65     101         MIT Subnet Support                    [NC3]
       66-68 102-104         Unassigned                            [JBP]
          69     105         SATNET Monitoring                    [DM11]
          70     106         Unassigned                            [JBP]
          71     107         Internet Packet Core Utility         [DM11]
       72-75 110-113         Unassigned                            [JBP]
          76     114         Backroom SATNET Monitoring           [DM11]
          77     115         Unassigned                            [JBP]
          78     116         WIDEBAND Monitoring                  [DM11]
          79     117         WIDEBAND EXPAK                       [DM11]
      80-254 120-376         Unassigned                            [JBP]
         255     377         Reserved                              [JBP]

###  Header Checksum :  16 bits

A checksum on the header only.  Since some header fields change
(e.g., time to live), this is recomputed and verified at each point
that the internet header is processed.

The checksum algorithm is:

The checksum field is the 16 bit one's complement of the one's
complement sum of all 16 bit words in the header.  For purposes of
computing the checksum, the value of the checksum field is zero.

###  Source Address:  32 bits

The source IPv4 address

###  Destination Address:  32 bits

The destination IPv4 address

### Options : optional

What is optional is their transmission in any particular datagram, not their
implementation.

### Padding :  variable

The internet header padding is used to ensure that the internet
header ends on a 32 bit boundary.  The padding is zero.
