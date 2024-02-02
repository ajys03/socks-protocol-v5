# socks-protocol-v5
[SOCKS Protocol Version 5](https://pages.github.com/).

Currently, the proxy is able to resolve IPv4 addresses. 
However, does not work with IPv6 or DOMAIN NAME. 

Use this command to test:
``` curl -vvv  -x socks5h://127.0.0.1:1080 https://1.1.1.1```.

This command allows so there is no name resolving done locally by curl (SOCKS5-hostname version).
