- udp Port  161 For Client-Server Comunication
- UDP Port 162 For SNMP Traps


Simple Network Management Protocol (SNMP) was created to monitor network devices. In addition, this protocol can also be used to handle configuration tasks and change settings remotely. SNMP-enabled hardware includes routers, switches, servers, IoT devices, and many other devices that can also be queried and controlled using this standard protocol. Thus, it is a protocol for monitoring and managing network devices. In addition, configuration tasks can be handled, and settings can be made remotely using this standard.

In addition to the pure exchange of information, SNMP also transmits control commands using agents over UDP port 161. The client can set specific values in the device and change options and settings with these commands. While in classical communication, it is always the client who actively requests information from the server, SNMP also enables the use of so-called traps over UDP port 162. These are data packets sent from the SNMP server to the client without being explicitly requested. If a device is configured accordingly, an SNMP trap is sent to the client once a specific event occurs on the server-side.

For the SNMP client and server to exchange the respective values, the available SNMP objects must have unique addresses known on both sides. This addressing mechanism is an absolute prerequisite for successfully transmitting data and network monitoring using SNMP.


# Dangerous Settings

|Settings 	  |      Description|
|------------|-------------|
rwuser noauth 	         |                               Provides access to the full OID tree without
authentication.
rwcommunity <community string> <IPv4 address> 	    |    Provides access to the full OID tree regardless of where the requests were sent from.
rwcommunity6 <community string> <IPv6 address> 	   |     Same access as with rwcommunity with the 
difference of using IPv6.


# Footprinting the Service
        
For footprinting SNMP, we can use tools like snmpwalk, onesixtyone, and braa. Snmpwalk is used to query the OIDs with their information. Onesixtyone can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator. Since these community strings can be bound to any source, identifying the existing community strings can take quite some time.

```
            $ snmpwalk -v2c -c public x.x.x.x

            $ onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt x.x.x.x

            $  braa <community string>@<IP>:.1.3.6.*
```
            