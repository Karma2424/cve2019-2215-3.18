mount -t tmpfs tmpfs /sbin && cp /data/data/mobi.omegacentauri.su98/su98 /sbin && cd /sbin && ln -s su98 su && chmod 755 su98 \
    && ln -s /data/local/tmp/su98-whitelist.txt . && ln -s /data/local/tmp/su98-denied.txt .
    
