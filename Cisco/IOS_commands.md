


# Zone-based Policy Firewalls

```
! Start with :

R1 > en
R1 # config t

to enter config mode
```

### Rules

- Traffic inside the same zone is not filtered
    - this apllys to different interfaces configured to be in the same zone

- An interface can belong to only one zone 

- An interface will have either classic stateless firewall or zpf, not both.
    - Remove classic config from **ip inspect**
    - Then apply zone-member security to interface

- Traffic only travels between zones.
    - Zone -> Zone
    - Not configured iface -> not configured iface
    - zone-member command has temporary interupt results until onether zone applys

- **Drop all Traffic** by default in inter-zone traffic ,if not otherwise specified by policy mapping

- Traffic originated from Routers themselves is not filtered


### Create a zone


```
Router(config)# zone security {zone-name}

- - - 

Router(config-sec-zone)# exit
```


### Create class-maps

- Class : identifies a set of packets based on its contents using “match” conditions.

- Class-maps : The way to define classes.

- inspect type is the appropriate for ZPF`s
```
Router(config)# class-map type inspect [match-any | match-all] {class-map-name}
```

example

```
Router(config-cmap)# match access-group {acl-# | acl-name }

Router(config-cmap)# match protocol protocol-name

Router(config-cmap)# match class-map class-map-name
```

- match access-group : match criteria config based on acl

- match protocol : class-map based on protocol

- match class-map : config based on preexisting class-map


example

create HTTP-TRAFFIC class-map and apply to R1

```
R1(config)# class-map type inspect match-any HTTP-TRAFFIC
R1(config-cmap)# match protocol http
R1(config-cmap)# match protocol https
R1(config-cmap)# match protocol dns
```

### Configure Policy-maps


- Action : can be inspect, drop ,pass.

```
Router(config)# policy-map type inspect {policy-map-name}

Router(config-pmap)# class type inspect {class-map-name}

Router(config-pmap-c)# {inspect | drop | pass}

```

### Match Zone-Pair -> Policy

Create a Zone-Pair with ***zone-pair security*** and match it to a policy with  ***service-policy type inspect***

```
Router(config)# zone-pair security zone-pair-name source {{source-zone-name }| self} destination {{destination-zone-name }| self}

Router(config-sec-zone-pair)# service-policy type inspect {policy-map-name }
```

example

```
R1(config)# zone-pair security PRIV-PUB source PRIVATE destination PUBLIC

R1(config-sec-zone-pair)# service-policy type inspect PRIV-TO-PUB-POLICY 
```

### Attach zones to interfaces

if no policy is aplied to zone all traffice will be dropped

```

Router(config-if)# zone-member security zone-name

```

example

```

R1(config)# interface GigabitEthernet 0/0
R1(config-if)# zone-member security PRIVATE
R1(config-if)# interface Serial 0/0/0
R1(config-if)# zone-member security PUBLIC
```

### Verify Configuration

```
R1# show run | begin class-map
```

Output is structured as follows:

    class-Maps

        |
        |
        |
    Policy-Maps
        |
        |
        |
    Zone-Pairing
        |
        |
        |
    Zone Configuration


#### Some more commands

```R1# show class-map type inspect```

```R1# show zone security```

```R1# show policy-map type inspect```

