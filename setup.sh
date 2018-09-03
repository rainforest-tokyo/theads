#sudo iptables -I INPUT -d $1 -p udp -dport 53 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT --protocol udp --dport 53 -j NFQUEUE --queue-num 2
