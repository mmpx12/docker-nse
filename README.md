# DOCKER NSE SCRIPT

![img](res.png)

## Install 

```sh
sudo cp docker.lua /usr/share/nmap/scripts/docker.nse
sudo nmap --script-update
```

## Usage

```sh
nmap -p2376 --script docker <IP>
```
