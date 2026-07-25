# Gotchas

### in_array()

- [in_array](https://www.php.net/manual/en/function.in-array.php) function searches if the first parameter exists in the array(second parameter).
- But there is a third boolean parameter that makes the comparison strict which defaults to **false**
- Here `file['name']` set to `5shell.php` passes the check and leads to arbitary file write.  

```php
public function __construct($file) {
    $this->file = $file;
    $this->whitelist = range(1, 24);
}
public function __destruct() {
    if (in_array($this->file['name'], $this->whitelist)) {
        move_uploaded_file(
            $this->file['tmp_name'],
            self::UPLOAD_DIRECTORY . $this->file['name']
        );
    }
}
```


### filter_var($input, FILTER_VALIDATE_URL)

- [fitler_var](https://www.php.net/manual/en/function.filter-var.php) is used to apply filters and sanitization to variables that come from user input.

- The above example is used with a FILTER_VALIDATE_URL filter to validate the next_slide url parameter is a valid url, based on [RFC 2396](https://datatracker.ietf.org/doc/html/rfc2396)
- Then injected to the rendered index.html by twig.


```php

class Template {
    private $twig;

    public function __construct() {
        $indexTemplate = '<img ' .
            'src="https://loremflickr.com/320/240">' .
            '<a href="{{link|escape}}">Next slide »</a>';

        // Default twig setup, simulate loading
        // index.html file from disk
        $loader = new Twig\Loader\ArrayLoader([
            'index.html' => $indexTemplate
        ]);
        $this->twig = new Twig\Environment($loader);
    }

    public function getNexSlideUrl() {
        $nextSlide = $_GET['nextSlide'];
        return filter_var($nextSlide, FILTER_VALIDATE_URL);
    }

    public function render() {
        echo $this->twig->render(
            'index.html',
            ['link' => $this->getNexSlideUrl()]
        );
    }
}

(new Template())->render();
```

- a javascript uri must be followed by a `://` in order to pass the validation of filter_var
- Injecting a new line will avoid the rest of js code to be comented out and get executed.

```php
<?php
echo filter_var('javascript:x%0aalert()', FILTER_VALIDATE_URL);
?>
// 
```

```php
<?php
echo filter_var('javascript://x%0aalert()', FILTER_VALIDATE_URL);
?>
//javascript://x%0aalert()
```


### new $userinputConstructor($userdata)

- A developer can create objects dynamically using user input , both as data passed as input to these constructors , as well as the Object constructors themselves.


```php
$controllerName = $_GET['c'];
$data = $_GET['d'];

if (class_exists($controllerName)) {
    $controller = new $controllerName($data['t'], $data['v']);
    $controller->render();
} else {
    echo 'There is no page with this name';
}
```

- This can lead to all kinds of exploit primitives , depending on available classes in the executing context.

- One useful class is the builtin `SimpleXMLElement`, introducing potential [XXE exploits](https://www.sonarsource.com/blog/shopware-php-object-instantiation-to-blind-xxe/)


### if (!strpos($var,$data)) for sanitization

- [strpos](https://www.php.net/strpos) returns the position of a substring in a string.

- Sometimes falsely used for checks of input string in an if statement.

- But if the first characters of user input contains  the substring, strpos returns a zero, typecasted to `false`.

- in the above XXE is possible by providing `user=<"><injected-tag%20property="`


```php
class Login {
    public function __construct($user, $pass) {
        $this->loginViaXml($user, $pass);
    }

    public function loginViaXml($user, $pass) {
        if (
            (!strpos($user, '<') || !strpos($user, '>')) &&
            (!strpos($pass, '<') || !strpos($pass, '>'))
        ) {
            $format = '<?xml version="1.0"?>' .
                      '<user v="%s"/><pass v="%s"/>';
            $xml = sprintf($format, $user, $pass);
            $xmlElement = new SimpleXMLElement($xml);
            // Perform the actual login.
            $this->login($xmlElement);
        }
    }
}
```

- Fixed :

```php
if (
    strpos($user,'<') === false && strpos($user,'>') === false
){

}
```

# preg_replace("/[^a-z.-_]/", "", $token);

- It is obvious that the intended usage of this regex is to delete every character that is not lowercase letter, dots , hyphens and underscores from the token.

- but for some reason the developer though that the first hyphen creates a range but the second one does not .

- so the range from . (46) to underscore (95) remains in the token.


# parse_str($url)

- 