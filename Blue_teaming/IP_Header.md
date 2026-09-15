
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




# IPv6 Header

-  header length is fixed size 40 bytes, comparing to the variable length size of the IPv4 header


```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  Traffic Class|          Flow Label                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Destination                                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Address                                                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


### Version : 4 bits

- In contrast to IPv4 , here its eq to 6 (0x0110)

### Traffic Class : 8 bits

- Similar concept as the Type of Service field in the IPv4 header, its the identifier of the packet’s class or priority


### Flow Label : 20 bits

-  indicates to intermediate devices that a packet belongs to a specific sequence of packets between a source and a destination


### Payload Length : 16 bits

- the length in bytes of the data portion of a packet including any IPv6 Extension headers ( does not include the main IPv6 header)

### Next Header : 8 bits

- either the type of the first extension header (if any) or the upper-layer protocol in the payload such as TCP, UDP, or ICMPv6

- similar to the IPv4 Protocol field

- When indicating an upper-layer protocol, the IPv6 Next Header field uses the same values that are used in the IPv4 Protocol.

|Next Header value (in hex) 	|Description|
|----------------------------|------------|
6 	|Transmission Control Protocol (TCP)
11 |	User Datagram Protocol (UDP)
2F |	Generic Routing Encapsulation (GRE)
32 |	Encapsulating Security Payload (ESP)
3A |	Internet Control Message Protocol version 6 (ICMPv6)
3B |	No Next Header for IPv6
59 	|Open Shortest Path First (OSPF)


### Hop Limit : 8 bits

- Basically ttl field

### Source Address : 128 bits

### Destination Address : 128 bits


## Example addresses


- Example 1 - The match-all address
```
IPv6 address - 0000:0000:0000:0000:0000:0000:0000:0000
Shortened - ::
```

- Example 2 - The loopback address
```
IPv6 address - 0000:0000:0000:0000:0000:0000:0000:0001
Shortened - ::1
```

- Example 3 - The all-nodes address
-  This is the v6 alternative to the well-known 224.0.0.1 in IPv4
```
IPv6 address - ff02:0000:0000:0000:0000:0000:0000:0001
Shortened - ff02::1
```

## IPv6 Address Types

### Unicast:  is one-to-one communication
- At present, all global unicast addresses start with binary value 001 (2000::/3)

- Link local is a special type of unicast address that is auto-configured on any interface using a combination of the link-local prefix FE80::/10
   - a local unicast address automatically assigned to every network interface enabled for IPv6
   - valid only for communications on a local link


- Embedded IPv4-in-IPv6
   - has only zeros in the first 96-bits of the address and an IPv4 address in the rightmost 32-bits
   - Examples :    `0:0:0:0:0:0:A:B:C:D` , `::A:B:C:D`


### Multicast: one-to-many communication

- distinguished from all other types by the value of the leftmost 8 bits of the addresses: a value of 11111111 (hex digits FF)

- all multicast addresses are part of the prefix ff00::/8, which is equivalent to the IPv4 multicast address space of 224.0.0.0/4.



### Anycast
- delivered to the "closest" interface identified by that address

- Anycast addresses are allocated from the unicast address space, therefore they are indistinguishable from global unicast addresses. 


