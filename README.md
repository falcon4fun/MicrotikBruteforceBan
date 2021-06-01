# MicrotikBruteforceBan
Attempt to rewrite https://github.com/falcon4fun/IptablesBruteforceBan for Mikrotik firewall

Logic is the same except there is no recent and set modules. Only internal adress lists.  
We will use them with dst-limit to count connections of IP per given time.

# Script
1. We need to check some input ports on WAN interface (vpn ports). I've put before drop invalid. SSH Chain will be created on the end.  
```
add action=jump chain=input comment="bruteforce input" connection-state=new dst-port=1194,1723 in-interface-list=WAN jump-target=SSH protocol=tcp
add action=jump chain=input connection-state=new dst-port=500,1701,4500 in-interface-list=WAN jump-target=SSH protocol=udp
```
2. We need to ban port scanners.  
```
add action=add-src-to-address-list address-list=Port_Scanners address-list-timeout=none-dynamic chain=input comment="address list portscanners" in-interface-list=WAN log-prefix=psd protocol=tcp psd=9,3s,3,1
``` 
3. Check additional ports. Settings up honeypot ports. There is a huge amount of scans of 1024,8291 and 8728. Futhermore, I've set RDP ports here except my ones which I forwarded. This is the last rule of input before "defconf: drop all not coming from LAN"
```
add action=jump chain=input comment="bruteforce input" connection-state=new dst-port=22-23 in-interface-list=WAN jump-target=SSH protocol=tcp
add action=jump chain=input connection-state=new dst-port=1024,8291,8728 in-interface-list=WAN jump-target=HONEY protocol=tcp
add action=jump chain=input connection-state=new dst-port=3377-3387,3390-3398 in-interface-list=WAN jump-target=HONEY protocol=tcp
```
4. Then I set some rules for FORWARD chain. There will be all forwarded ports I need to check. Put them before FORWARD "defconf: drop invalid" rule 
```
add action=jump chain=forward comment="bruteforce forward" connection-state=new dst-port=3389,3399 in-interface-list=WAN jump-target=RDP protocol=tcp
add action=jump chain=forward connection-state=new dst-port=3389,3399 in-interface-list=WAN jump-target=RDP protocol=udp
add action=jump chain=forward connection-state=new dst-port=21 in-interface-list=WAN jump-target=FTP protocol=tcp
add action=jump chain=forward connection-state=new dst-port=3773,9875 in-interface-list=WAN jump-target=PROXY protocol=tcp 
add action=jump chain=forward connection-state=new dst-port=3773,9875 in-interface-list=WAN jump-target=PROXY protocol=udp
```
5. You need to create corresponding chains
```
add action=passthrough chain=HONEY comment=HONEY disabled=yes  
add action=jump chain=HONEY jump-target=HONEY2  
add action=jump chain=HONEY jump-target=HONEY1  
add action=passthrough chain=FTP comment=FTP disabled=yes  
add action=return chain=FTP dst-limit=5/2m,5,src-address/2m log-prefix="FTP RETURN"  
add action=add-src-to-address-list address-list=FTP_Ban address-list-timeout=none-dynamic chain=FTP log=yes log-prefix="FTP BAN"  
add action=drop chain=FTP  
add action=return chain=HONEY1 comment=HONEY1 dst-limit=7/30m,7,src-address/30m log-prefix="HONEY1 RETRUN"  
add action=add-src-to-address-list address-list=HONEY_Ban address-list-timeout=1w chain=HONEY1 log=yes log-prefix=HONEY_BAN  
add action=drop chain=HONEY1  
add action=return chain=HONEY2 comment=HONEY2 dst-limit=15/2h,15,src-address/2h log-prefix="HONEY2 RETRUN"  
add action=add-src-to-address-list address-list=HONEY_Ban address-list-timeout=1w chain=HONEY2 log=yes log-prefix=HONEY_BAN  
add action=drop chain=HONEY2  
add action=passthrough chain=PROXY comment=PROXY  
add action=jump chain=RDP comment=RDP jump-target=RDP3  
add action=jump chain=RDP jump-target=RDP2  
add action=jump chain=RDP jump-target=RDP1  
add action=return chain=RDP1 comment=RDP1 dst-limit=3/5m,3,src-address/5m log-prefix="RDP1 RETRUN"  
add action=add-src-to-address-list address-list=RDP_Timeout address-list-timeout=10m chain=RDP1 log=yes log-prefix=RDP_Timeout  
add action=drop chain=RDP1  
add action=reject chain=RDP1 disabled=yes protocol=tcp reject-with=tcp-reset  
add action=reject chain=RDP1 disabled=yes reject-with=icmp-port-unreachable  
add action=return chain=RDP2 comment=RDP2 dst-limit=9/2h,9,dst-address/2h log-prefix="RDP2 RETURN"  
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=RDP2 log=yes log-prefix="RDP2 BAN"  
add action=drop chain=RDP2  
add action=reject chain=RDP2 disabled=yes protocol=tcp reject-with=tcp-reset  
add action=reject chain=RDP2 disabled=yes reject-with=icmp-port-unreachable  
add action=return chain=RDP3 comment=RDP3 dst-limit=14/1d,14,src-address/1d log-prefix="RDP3 RETURN"  
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=RDP3 log=yes log-prefix="RDP3 BAN"  
add action=drop chain=RDP3  
add action=reject chain=RDP3 disabled=yes protocol=tcp reject-with=tcp-reset  
add action=reject chain=RDP3 disabled=yes reject-with=icmp-port-unreachable  
add action=jump chain=SSH comment=SSH jump-target=SSH2  
add action=jump chain=SSH jump-target=SSH1  
add action=return chain=SSH1 comment=SSH1 dst-limit=5/2m,5,src-address/2m log-prefix="SSH RETURN"  
add action=add-src-to-address-list address-list=SSH_Ban address-list-timeout=5m chain=SSH1 log=yes log-prefix="SSH1 BAN"  
add action=drop chain=SSH1  
add action=return chain=SSH2 comment=SSH2 dst-limit=10/6h,10,src-address/6h log-prefix="SSH RETURN"  
add action=add-src-to-address-list address-list=SSH_Ban address-list-timeout=1w chain=SSH2 log=yes log-prefix="SSH2 BAN"  
add action=drop chain=SSH2
```
6. One more thing to go. We need to ban IPs from address-lists in RAW table. Why raw? Because we want to optimize resources. RAW prerouting is the one of the first tables packet hits
```
add action=drop chain=prerouting src-address-list=Port_Scanners
add action=drop chain=prerouting src-address-list=HONEY_Ban
add action=drop chain=prerouting src-address-list=FTP_Ban
add action=drop chain=prerouting src-address-list=SSH_Ban
add action=jump chain=prerouting disabled=yes dst-limit=5/1m,5,dst-address/1m40s jump-target=TMP_Ban src-address-list=RDP_Ban
add action=drop chain=prerouting log-prefix="RAW RDP_Ban DROP" src-address-list=RDP_Ban
add action=jump chain=prerouting jump-target=TMP_Timeout src-address-list=RDP_Timeout
add action=drop chain=prerouting log-prefix="RAW RDP_Timeout DROP" src-address-list=RDP_Timeout
add action=return chain=TMP_Ban comment=TMP_Ban disabled=yes dst-limit=30/30m,30,src-address/30m
add action=passthrough chain=TMP_Ban disabled=yes
add action=return chain=TMP_Timeout comment=TMP_Timeout dst-limit=5/30m,5,src-address/30m
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=TMP_Timeout log=yes log-prefix=TMP_Timeout
```
# Optimization
The script is quite "dirty". There is no any recent and set module so I need to use what I have. I think this is the best way for me as it is a script for home.  
Some chains can be merged but I prefer better look. That's why I use RDP1, RDP2, .. RDPn in RDP chain to beatify it. I don't think redirecting from one chain to another without any conditions will consume very much CPU time.  
Moreover some rules can be combined. I.e. first paragraph can be combined to dst-port=1194,1723,500,1701,4500 but I prefer more statistics like packet count in firewall tab to analyze.  
It's quite dirty way to use dst-limit. You need to loosen my values for your needs. I.e. server or high loaded port with legit new connections. I need RDP, VPN and etc ports from WAN one time per over9000 days. So the rules are very strict and can ban legit things.  
Chain1, Chain2, ChainN are for double checking. Some bruteforcers have a lot of IPs and can come after 2-6 hours, as I mentioned in IptablesBan script.  
Some rules are disabled because I'm too lazy to make it for production use. So please clean disabled ones by yourself. In example, reject ones from filter. They moved to raw :)


# Complete firewall script
```
/ip firewall export

/ip firewall filter
add action=accept chain=input comment="defconf: accept established,related,untracked" connection-state=established,related,untracked
add action=accept chain=input protocol=ipsec-esp
add action=accept chain=input protocol=ipsec-ah
add action=jump chain=input comment="bruteforce input" connection-state=new dst-port=1194,1723 in-interface-list=WAN jump-target=SSH protocol=tcp
add action=jump chain=input connection-state=new dst-port=500,1701,4500 in-interface-list=WAN jump-target=SSH protocol=udp
add action=accept chain=input comment="allow IPsec NAT" dst-port=4500 protocol=udp
add action=accept chain=input comment="allow IKE" dst-port=500 protocol=udp
add action=accept chain=input comment="allow l2tp" dst-port=1701 protocol=udp
add action=accept chain=input comment="allow pptp" dst-port=1723 protocol=tcp
add action=accept chain=input comment="allow openvpn" dst-port=1194 protocol=tcp
add action=accept chain=input comment="allow sstp" disabled=yes dst-port=443 protocol=tcp
add action=accept chain=input comment="allow pptp gre" disabled=yes protocol=gre
add action=drop chain=input comment="defconf: drop invalid" connection-state=invalid log-prefix="DROP INVALID INPUT"
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment="defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=add-src-to-address-list address-list=Port_Scanners address-list-timeout=none-dynamic chain=input comment="address list portscanners" in-interface-list=WAN log-prefix=psd protocol=tcp psd=9,3s,3,1
add action=accept chain=input comment="allow vpns to lan" in-interface-list=VPN log-prefix="PPTP TCP"
add action=jump chain=input comment="bruteforce input" connection-state=new dst-port=22-23 in-interface-list=WAN jump-target=SSH protocol=tcp
add action=jump chain=input connection-state=new dst-port=1024,8291,8728 in-interface-list=WAN jump-target=HONEY protocol=tcp
add action=jump chain=input connection-state=new dst-port=3377-3387,3390-3398 in-interface-list=WAN jump-target=HONEY protocol=tcp
add action=accept chain=input comment="winbox remote" disabled=yes dst-port=8291 protocol=tcp
add action=drop chain=input comment="defconf: drop all not coming from LAN" in-interface-list=!LAN log-prefix="DROP NOT LAN:"
add action=accept chain=forward comment="defconf: accept in ipsec policy" ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" connection-state=established,related
add action=accept chain=forward comment="defconf: accept established,related, untracked" connection-state=established,related,untracked
add action=jump chain=forward comment="bruteforce forward" connection-state=new dst-port=3389,3399 in-interface-list=WAN jump-target=RDP protocol=tcp
add action=jump chain=forward connection-state=new dst-port=3389,3399 in-interface-list=WAN jump-target=RDP protocol=udp
add action=jump chain=forward connection-state=new disabled=yes dst-port=3399 in-interface-list=WAN jump-target=RDP protocol=tcp
add action=jump chain=forward connection-state=new disabled=yes dst-port=3399 in-interface-list=WAN jump-target=RDP protocol=udp
add action=jump chain=forward connection-state=new dst-port=21 in-interface-list=WAN jump-target=FTP protocol=tcp
add action=jump chain=forward connection-state=new dst-port=3773,9875 in-interface-list=WAN jump-target=PROXY protocol=tcp
add action=jump chain=forward connection-state=new dst-port=3773,9875 in-interface-list=WAN jump-target=PROXY protocol=udp
add action=drop chain=forward comment="defconf: drop invalid" connection-state=invalid log-prefix="DROP INVALID FORWARD"
add action=drop chain=forward comment="defconf: drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
add action=passthrough chain=HONEY comment=HONEY disabled=yes
add action=jump chain=HONEY jump-target=HONEY2
add action=jump chain=HONEY jump-target=HONEY1
add action=passthrough chain=FTP comment=FTP disabled=yes
add action=return chain=FTP dst-limit=5/2m,5,src-address/2m log-prefix="FTP RETURN"
add action=add-src-to-address-list address-list=FTP_Ban address-list-timeout=none-dynamic chain=FTP log=yes log-prefix="FTP BAN"
add action=drop chain=FTP
add action=return chain=HONEY1 comment=HONEY1 dst-limit=7/30m,7,src-address/30m log-prefix="HONEY1 RETRUN"
add action=add-src-to-address-list address-list=HONEY_Ban address-list-timeout=1w chain=HONEY1 log=yes log-prefix=HONEY_BAN
add action=drop chain=HONEY1
add action=return chain=HONEY2 comment=HONEY2 dst-limit=15/2h,15,src-address/2h log-prefix="HONEY2 RETRUN"
add action=add-src-to-address-list address-list=HONEY_Ban address-list-timeout=1w chain=HONEY2 log=yes log-prefix=HONEY_BAN
add action=drop chain=HONEY2
add action=passthrough chain=PROXY comment=PROXY
add action=jump chain=RDP comment=RDP jump-target=RDP3
add action=jump chain=RDP jump-target=RDP2
add action=jump chain=RDP jump-target=RDP1
add action=return chain=RDP1 comment=RDP1 dst-limit=3/5m,3,src-address/5m log-prefix="RDP1 RETRUN"
add action=add-src-to-address-list address-list=RDP_Timeout address-list-timeout=10m chain=RDP1 log=yes log-prefix=RDP_Timeout
add action=drop chain=RDP1
add action=reject chain=RDP1 disabled=yes protocol=tcp reject-with=tcp-reset
add action=reject chain=RDP1 disabled=yes reject-with=icmp-port-unreachable
add action=return chain=RDP2 comment=RDP2 dst-limit=9/2h,9,dst-address/2h log-prefix="RDP2 RETURN"
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=RDP2 log=yes log-prefix="RDP2 BAN"
add action=drop chain=RDP2
add action=reject chain=RDP2 disabled=yes protocol=tcp reject-with=tcp-reset
add action=reject chain=RDP2 disabled=yes reject-with=icmp-port-unreachable
add action=return chain=RDP3 comment=RDP3 dst-limit=14/1d,14,src-address/1d log-prefix="RDP3 RETURN"
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=RDP3 log=yes log-prefix="RDP3 BAN"
add action=drop chain=RDP3
add action=reject chain=RDP3 disabled=yes protocol=tcp reject-with=tcp-reset
add action=reject chain=RDP3 disabled=yes reject-with=icmp-port-unreachable
add action=jump chain=SSH comment=SSH jump-target=SSH2
add action=jump chain=SSH jump-target=SSH1
add action=return chain=SSH1 comment=SSH1 dst-limit=5/2m,5,src-address/2m log-prefix="SSH RETURN"
add action=add-src-to-address-list address-list=SSH_Ban address-list-timeout=5m chain=SSH1 log=yes log-prefix="SSH1 BAN"
add action=drop chain=SSH1
add action=return chain=SSH2 comment=SSH2 dst-limit=10/6h,10,src-address/6h log-prefix="SSH RETURN"
add action=add-src-to-address-list address-list=SSH_Ban address-list-timeout=1w chain=SSH2 log=yes log-prefix="SSH2 BAN"
add action=drop chain=SSH2
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" ipsec-policy=out,none out-interface-list=WAN
add action=masquerade chain=srcnat comment="masq. vpn traffic" log=yes log-prefix="VPN MASQ" src-address=10.0.1.0/24
add action=dst-nat chain=dstnat comment="Force local DNS" dst-port=53 protocol=tcp to-addresses=192.168.0.1 to-ports=53
add action=dst-nat chain=dstnat dst-port=53 protocol=udp to-addresses=192.168.0.1 to-ports=53
add action=dst-nat chain=dstnat comment="OpenVpn Netgear" disabled=yes dst-port=1194 in-interface-list=WAN log-prefix="OVPN CON" protocol=udp to-addresses=192.168.0.2 to-ports=1194
add action=dst-nat chain=dstnat comment="PPTP Netgear" disabled=yes dst-port=1723 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.2 to-ports=1723
add action=dst-nat chain=dstnat comment=FTP dst-port=21 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.101 to-ports=21
add action=dst-nat chain=dstnat dst-port=990 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.101 to-ports=990
add action=dst-nat chain=dstnat comment=RDP1 dst-port=3388 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.100 to-ports=3389
add action=dst-nat chain=dstnat dst-port=3388 in-interface-list=WAN protocol=udp to-addresses=192.168.0.100 to-ports=3389
add action=dst-nat chain=dstnat comment=RDP2 dst-port=3399 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.101 to-ports=3399
add action=dst-nat chain=dstnat dst-port=3399 in-interface-list=WAN protocol=udp to-addresses=192.168.0.101 to-ports=3399
add action=dst-nat chain=dstnat comment=Torrent dst-port=54321 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.100 to-ports=54321
add action=dst-nat chain=dstnat dst-port=54321 in-interface-list=WAN protocol=udp to-addresses=192.168.0.100 to-ports=54321
add action=dst-nat chain=dstnat comment=Proxy dst-port=3773 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.101 to-ports=3773
add action=dst-nat chain=dstnat dst-port=3773 in-interface-list=WAN protocol=udp to-addresses=192.168.0.101 to-ports=3773
add action=dst-nat chain=dstnat dst-port=9785 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.101 to-ports=9785
add action=dst-nat chain=dstnat dst-port=9785 in-interface-list=WAN protocol=udp to-addresses=192.168.0.101 to-ports=9785
add action=dst-nat chain=dstnat comment="Torrent Tablet" dst-port=54323 in-interface-list=WAN protocol=tcp to-addresses=192.168.0.110 to-ports=54323
add action=dst-nat chain=dstnat dst-port=54323 in-interface-list=WAN protocol=udp to-addresses=192.168.0.110 to-ports=54323
add action=dst-nat chain=dstnat comment="Steam Ports" dst-port=27000-27100 in-interface-list=WAN protocol=udp to-addresses=192.168.0.100 to-ports=27000-27100
/ip firewall raw
add action=drop chain=prerouting src-address-list=Port_Scanners
add action=drop chain=prerouting src-address-list=HONEY_Ban
add action=drop chain=prerouting src-address-list=FTP_Ban
add action=drop chain=prerouting src-address-list=SSH_Ban
add action=jump chain=prerouting disabled=yes dst-limit=5/1m,5,dst-address/1m40s jump-target=TMP_Ban src-address-list=RDP_Ban
add action=drop chain=prerouting log-prefix="RAW RDP_Ban DROP" src-address-list=RDP_Ban
add action=jump chain=prerouting jump-target=TMP_Timeout src-address-list=RDP_Timeout
add action=drop chain=prerouting log-prefix="RAW RDP_Timeout DROP" src-address-list=RDP_Timeout
add action=return chain=TMP_Ban comment=TMP_Ban disabled=yes dst-limit=30/30m,30,src-address/30m
add action=passthrough chain=TMP_Ban disabled=yes
add action=return chain=TMP_Timeout comment=TMP_Timeout dst-limit=5/30m,5,src-address/30m
add action=add-src-to-address-list address-list=RDP_Ban address-list-timeout=none-dynamic chain=TMP_Timeout log=yes log-prefix=TMP_Timeout
```
