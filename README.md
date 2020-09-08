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
