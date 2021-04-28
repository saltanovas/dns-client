# DNS Client
The implementation of a DNS client that performs a lookup in order to translate a domain name to an IP address. **Take a note that program supports UNIX based OS only**.

## Compilation
The following command compiles the program:
```
gcc main.c -o Program
```

## Execution
Please use `a` prefix to get an IPv4 address or `aaaa` to get an IPv6:
```
./program {[domain_name] {a | aaaa}}
```
Read more information about the DNS protocol at https://www.ietf.org/rfc/rfc1035.txt
