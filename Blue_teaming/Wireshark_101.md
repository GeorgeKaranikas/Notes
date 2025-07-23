


# Exporting Files from packet streams



## HTTP Traffic

- Filter on http.request and find the GET requests and the files to be extracted

- Go to File → Export Objects → HTTP...

- Choose the file and **Save**


! We can also review html pages this way


## SMTP unencrypted traffic

- Filter for smtp.data.fragment

- Go to File → Export Objects → IMF...

- Internet Message Format can be saved to .eml files which is printable text


## FTP Traffic

- Filter for ftp.request.command or (ftp-data and tcp.seq eq 1)

- Go to File → Export Objects → FTP-DATA...


#### You can also filter for specific strings 

- With ftp-data.command contains "string" and tcp.seq eq 1



## Exporting TCP Streams

- Some files are not in export menus cause they might be encrypted or not transimited normally

- Follow the tcp stream 

- Select RAW in "Show data as"

- Save as


## Exporting TLS Certificates

- Filter for tls.handshake.certificate

- Certificate is Under Transport Layer Security → Handshake Protocol : Certificate → Certificate

- Right Click and Export Packet Bytes



(Cool exercise HTB`s sherlock : Compromised)


# Finding hostname


## Through DHCP

- Filter for **dhcp**

- open a request and expand **DHCP->Options: Host Name





