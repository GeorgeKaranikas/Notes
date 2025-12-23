# Programming

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


## os.path.join(path, / , *paths)

- Returns a concatenation of path with paths.

- If one of the *paths variable of os.path.join(path,/,*paths) is absolute path , the return value has this as a basedir and the previous paths are ignored, including the first variable path.


```python
>>>os.path.join('/home/','/etc/passwd/')
/etc/passwd
```

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


