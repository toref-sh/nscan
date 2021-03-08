# nscan
Cross-platform Network Scan Tool for Security Testing, Network Management.    

## Basic Usage 
```
USAGE:
    nscan [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p, --port <ip_addr:port_range>    Port Scan - Ex: -p 192.168.1.8:1-1000
    -n, --host <ip_addr>               Scan hosts in specified network - Ex: -n 192.168.1.0
    -u, --uri <uri>                    URI Scan - Ex: -u http://192.168.1.8/xvwa/ -w common.txt
    -d, --domain <domain_name>         Domain Scan - Ex: -d example.com -w subdomain.txt
    -t, --timeout <duration>           Set timeout in ms - Ex: -t 10000
    -i, --interface <name>             Specify network interface by name - Ex: -i en0
    -w, --word <file_path>             Use word list - Ex: -w common.txt
    -s, --save <file_path>             Save scan result to file - Ex: -s result.txt

SUBCOMMANDS:
    update    Update nscan database
    help      Prints this message or the help of the given subcommand(s)
```
