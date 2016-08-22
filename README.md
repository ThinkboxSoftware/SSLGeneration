# Requirements

1. Python
2. The pyopenssl library.

```
pip install -r requirement.txt
```

# Usage

First generate the CA file

```
python ssl_gen.py --ca --cert-org Thinkbox --cert-ou IT
```
This will dump the ca keys in a folder aplty named 'keys'

Generate the server certificate
```
python ssl_gen.py --server --cert-name <cert_name>
```

This will create a server.crt and server.key file in the 'keys' folder.

Generate the client certificate
```
python ssl_gen.py --client --cert-name <cert_name>
```

Generate a pfx certificate
```
python ssl_gen.py --pfx --cert-name <cert_name>
```

