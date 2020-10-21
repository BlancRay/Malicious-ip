# Malicious-ip
A Malicious IP DataBase

## Usage
Just clone and load [ips file](./ips) to your firewall

- For ufw user:
  
    ```bash
    while read line; do
        sudo ufw deny from $line
    done < ips
    ```

or

- For iptables user:
  
    ```bash
    while read line; do
        iptables -I INPUT -s $line -j DROP
    done < ips
    ```

## Additional Tool
[autocombine_ips](./autocombine_ips.py) is a Python3 Script to count Malicious IP in each IP block
```Python
# *.*.*.*/32
if IP.block24.count > 24
    block(IP.block24)
    
# *.*.*.0/24
if IP.block16.count > 16
    block(IP.block16)
    
# *.*.0.0/16
if IP.block8.count > 8
    block(IP.block8)
```
