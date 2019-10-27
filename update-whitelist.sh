cd /data/local/tmp/su98-denied
tail -1 su98-denied.txt | cat - su98-whitelist.txt | sort | uniq > /data/local/tmp/su98-whitelist.txt
sed -i '$d' su98-denied.txt
