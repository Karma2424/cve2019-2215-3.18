set -e
( mount | grep "tmpfs on /sbin " ) || mount -t tmpfs tmpfs /sbin
cp /data/data/mobi.omegacentauri.su98/su98 /sbin
cd /sbin
chmod 755 su98
set +e
ln -s su98 su
ln -s /data/local/tmp/su98-whitelist.txt .
ln -s /data/local/tmp/su98-denied.txt .
cd /data/local/tmp
touch su98-denied.txt
chown shell.shell su98-denied.txt
chmod 644 su98-denied.txt 
