# JS Tricks

## Function code to string

- In JavaScript, you can get function body by casting it to a string:

```javascript
function a() {}
console.log(a+'')
// "function a() {}"
```



## Strict mode


### no-strict mode

#### arguments.callee

- In non-strict mode, arguments.callee returns it self for IIFE(Immediately Invoked Function Expression).
- However, 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode

```javascript
(function(){ return arguments.callee+''; /* flag */})()
"(function(){ return arguments.callee+''; /* flag */})()"
```


# Express

## Express query strings

- Express uses [qs](https://www.npmjs.com/package/qs) library to handle query strings
- By default qs, besides simple scalars ,accepts also arrays and objects
- It also groups query parameters with the same name.
- So an attacker can [bypass simple checks](https://str.lc/posts/corctf_2022_challenges/#simplewaf) for `req.query.var` by providing array query parameters

|Query string | req.query.file|
|------------|-----------------|
?file[]=1&file[]=2 | req.query.file=["1", "2"]
?file=1&file=2 | req.query.file=["1", "2"]
?file[a]=b&file[c]=d |req.query.file = {"a": "b", "c": "d"}
?[file]=a | req.query.file= "a"


### Simple checks

- If a query parameter is not asserted as a string
- But checks and transformations are applied to that variable later as it was a string
- An attacker could use this feature to subvert the logic of the application

- [redpwnCTF2020](https://github.com/TeamUnderdawgs/CTF-Docs/blob/master/redpwnCTF2020/Web/tux-fanpage.md)

```javascript

app.get('/page', (req, res) => {

    let path = req.query.path

    path = preventTraversal(path)

    res.sendFile(prepare(path), (err) => {
        if(err){
            if (! res.headersSent) {
                try {
                    res.send(strip(req.query.path) + ' not found')
                } catch {
                    res.end()
                }
            }
        }
    })
})
```

```javascript
function preventTraversal(dir){
    if(dir.includes('../')){
        let res = dir.replace('../', '')
        return preventTraversal(res)
    }
}
function strip(dir){
    const regex = /^[a-z0-9]$/im

    //Remove first character if not alphanumeric
    
    if(!regex.test(dir[0])){
        if(dir.length > 0){
            return strip(dir.slice(1))
        }
        return ''
    }

    return dir
}
```

- attacker would pass `path[]=a&path[]=/../../index.js`

- so `dir[0]` = `'a'` + `dir.slice[1]` = `/../../../idex.js`

- .includes() in an array has to be the whole string to return true (`/../../index.js`)

- String + Array in JS results to a string so , res.sendFile runs with a string path variable.


### Bypass checks

- If not strict equality `===` is checked, but instead its loose equivalent is used.
- An attacker can bypass the checks by using this behaviour of qs

[TetCTF-2023 - Image service viewer](https://github.com/RaccoonNinja/TetCTF-2023-Writeups/blob/main/Image%20Services%20Viewer.md)

```javascript
if (req.query.password.length > 12 || req.query.password != "Th!sIsS3xreT0") {
    return res.send(`You don't have permission\n${req.query.password.length}\n${req.query.password}`)
}
```

`?password[]=Th!sIsS3xreT0`
-  makes password an array of length 1, containing the string


### parser diffs - express.req.query.var - URLSearchParams(window.location.search).get(var)

- when qs is trying to parse url parameters , it prioritises `]=` over `=`
- thats because it needs to be able to group parameters to objects/arrays.
- but the parser doesnt checks exactly where the string `]=` is , or if another `=` occurs
- this way [parser differentials](https://blog.voorivex.team/when-two-parsers-disagree-exploiting-query-string-differentials-for-xss) are introduced


```javascript
app.get('/', (req, res) => {
  const redirectUri = req.query.redirect_uri;

  if (redirectUri !== "https://pwnbox.xyz/docs") {
    return res.send("Invalid redirect_uri");
  }

  return res.send(`
    <script>
      location = new URLSearchParams(window.location.search).get("redirect_uri");
    </script>
  `);
});
```

The qs parser sees:

 - <code style="color : Aqua">/?redirect_uri=javascript:alert(origin)//?x]=</code><code style="color : Red">x</code>&<code style="color : Aqua">redirect_uri=</code><code style="color : Red">https://pwnbox.xyz/docs</code>

The browser sees: 

 - <code style="color : Aqua">/?redirect_uri=</code><code style="color : Red">javascript:alert(origin)//?x]=x</code>&<code style="color : Aqua">redirect_uri=</code><code style="color : Red">https://pwnbox.xyz/docs</code>

### parser diffs - express max query parameters array - Browser query string

- Express has a default of 1000 sized array to parse the query string, while the rest of query parameters beyond that limit are ignored
- That creates a desync between node and the browser in the query string they "see"


```javascript
app.get('/', (req, res) => {
  const redirectUri = req.query.redirect_uri;

  if (redirectUri !== "https://pwnbox.xyz/docs") {
    return res.send("Invalid redirect_uri");
  }

  return res.send(`
    <script>
      location = new URLSearchParams(window.location.search).get("redirect_uri");
    </script>
  `);
});
```

`/?[redirect_uri]=https://pwnbox.xyz/docs&p&p&p...(×1000)...&p&redirect_uri=javascript:alert(origin)`

