Web proxies are specialized tools that can be set up between a browser/mobile application and a back-end server to capture and view all the web requests being sent between both ends, essentially acting as man-in-the-middle (MITM) tools.


  ## Installing CA Certificate

We can install Burp's certificate once we select Burp as our proxy in Foxy Proxy, by browsing to http://burp, and download the certificate from there by clicking on CA Certificate:

To get ZAP's certificate, we can go to (Tools>Options>Dynamic SSL Certificate), then click on Save:

Once we have our certificates, we can install them within Firefox by browsing to about:preferences#privacy, scrolling to the bottom, and clicking View Certificates:


After that, we can select the Authorities tab, and then click on import, and select the downloaded CA certificate:

Finally, we must select Trust this CA to identify websites and Trust this CA to identify email users, and then click OK: 


 ## Intercept

ZAP also has a powerful feature called Heads Up Display (HUD), which allows us to control most of the main ZAP features from right within the pre-configured browser. We can enable the HUD by clicking its button at the end of the top menu bar:

Now, once we refresh the page or send another request, the HUD will intercept the request and will present it to us for action:

#### Intercept Response

In Burp, we can enable response interception by going to (Proxy>Options) and enabling Intercept Response under Intercept Server Responses:

#### Automatic Request Modification

Let us start with an example of automatic request modification. We can choose to match any text within our requests, either in the request header or request body, and then replace them with different text. 

#### Burp Match and Replace

We can go to (Proxy>Options>Match and Replace) and click on Add in Burp. 

-    Type: Request header 	Since the change we want to make will be in the request header and not in its body.
-    Match: ^User-Agent.*$ 	The regex pattern that matches the entire line with User-Agent in it.
-   Replace: User-Agent: HackTheBox Agent 1.0 	This is the value that will replace the line we matched above.
-   Regex match: True 	We don't know the exact User-Agent string we want to replace, so we'll use regex to match any value that matches the pattern we specified above.




#### ZAP Replacer

ZAP has a similar feature called Replacer, which we can access by pressing [CTRL+R] or clicking on Replacer in ZAP's options menu.



#### Automatic Response Modification

The same concept can be used with HTTP responses as well.

Let us go back to (Proxy>Options>Match and Replace) in Burp to add another rule. This time we will use the type of Response body since the change we want to make exists in the response's body and not in its headers



## Proxychains

```
    /etc/proxychains.conf

    #socks4         127.0.0.1 9050
    http 127.0.0.1 8080
```
    
    
#### Nmap Proxying 

Next, let's try to proxy nmap through our web proxy.

```$ nmap -h | grep -i prox``` 


As we can see, we can use the --proxies flag. We should also add the -Pn flag to skip host discovery (as recommended on the man page). Finally, we'll also use the -sC flag to examine what an nmap script scan does:

```$nmap --proxies http://127.0.0.1:8080 SERVER_IP -pPORT -Pn -sC```



#### Metasploit Proxying 

to set a proxy for any exploit within Metasploit, we can use the set PROXIES flag. Let's try the robots_txt scanner as an example and run it against one of our previous exercises:



```
$ msfconsole

msf6 > use auxiliary/scanner/http/robots_txt
msf6 auxiliary(scanner/http/robots_txt) > set PROXIES HTTP:127.0.0.1:8080
```
    