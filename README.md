# Swift Container Keys Auth Middleware

Allows for access to containers based on a simple key rather than requiring
a user to supply Keystone credentials, and embed them in their application.

Container keys supports two keys, specifically X-Container-Meta-Full-Key and
X-Container-Meta-Read-Key. Whichever is supplied will be authenticated against.
Read-Key will only accept GET requests, not POST/PUT/DELETE, which would be
supported by Full-Key.

# Setup

Install the package!

Add the containerkeys api filter into your swift configuration file.

    [pipeline:main]
    pipeline = ... containerkeys ... auth ... proxy-server

    ...
    
    [filter:containerkeys]
    use = egg:containerkeys#containerkeys

the `containerkeys` middleware should appear before your authentication
middleware, so that you may bypass it when necessary.

# Usage

Using your swift credentials, create your Full or Read container keys using the
swift CLI tools.


    $ swift post -m "Read-Key:mysupersecretkey123" <container_name>
    $ swift post -m "Full-Key:thiskeywillhavewriteaccess" <container_name>


Test accessing your container using your new keys using `curl`


    $ curl -v -H 'X-Container-Meta-Read-Key:mysupersecreykey123' http://127.0.0.1:8080/v1/AUTH_test/container_name
    ...
    < HTTP/1.1 200 OK
    < X-Container-Object-Count: 1
    < 
    test-file.txt

    $ curl -v -H 'X-Container-Meta-Read-Key:BAD_KEY_' http://127.0.0.1:8080/v1/AUTH_test/container_name
    ...
    < HTTP/1.1 401 Unauthorized
    < 
    401 Unauthorized: Auth Key invalid

# Internal Structure

We store key data in Container Metadata, and it can contain any number of full and read keys to match.

```
Full-Key
Full-Key-1
Full-Key-2
Read-Key
Read-Key-1
```

which translates to the following structure on read:

```
{FULL: ['x', 'x1'],
 READ: ['y', 'y1']}
```

and validity is checked through an IN comparator. This allows for multiple read and full keys to exist on the container, and be checked by the middleware. The logic for deprecating and moving API key values is not part of the authentication middleware, and is to be implemented at the dashboard / application level.
