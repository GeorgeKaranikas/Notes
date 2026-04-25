# Ruby on Rails


## Params hash

- Query string is decoded in a ruby [hash](https://ruby-doc.org/core-2.5.8/Hash.html) called `params`
- The `params` hash also contains POST parameters from html forms (Content-Type: x-www-form-urlencoded)

- Access parameters

```ruby
 #  URL "/clients?status=activated"
def index
    if params[:status] == "activated"
        @clients = Client.activated
    else
        @clients = Client.inactivated
    end
end
```

- Simple parameters

```
username=hacker&password=happy

params = {"username"=>"hacker","password"=>"happy"}
```

- Passing arrays

```
GET /index.html?user[]=Phrack&user[]=rulez

params {"user" => ["Phrack","rulez"]}

params[:user] = ["Prhack","rulez"]
```

- Passing a hash

```

GET /index.html?user[name]=hacker&user[password]=happy

params = {"user"=>{"name"=>"hacker","password"=>"happy"}}
```

- Passing a nill value

```
GET /index.html?user[name]

params = {"user"=>{"name"=>nill} }
```

## RoR Gotcha`s


#### method confusion

- You can confuse the intermediaries by using the _method parameter
- this request will be rendered as an PUT Request

```bash
curl -X POST http://somerailsapp/?_method=PUT --data 'somedata'
```

#### Request data in GET Requests

```bash
 curl -X GET http://somerailsapp/ -H "Content-type: application/json" \
  --data '{"a":"z"}'
```

