#!/bin/bash

# cleanup
echo "[+] Cleaning up in case of failed run"
rm -f /tmp/blacklisted.zones
rm -f /tmp/blacklist.txt
rm -f /tmp/ads-list.txt
rm -f /tmp/mal-list.txt
rm -f /tmp/ran-list.txt

# get list of domains from different sources
echo "[+] Getting list of domains to blacklist"
wget -O /tmp/ads-list.txt 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=;showintro=0&&mimetype=plaintext'
wget -O /tmp/mal-list.txt 'http://mirror1.malwaredomains.com/files/justdomains'
wget -O /tmp/ran-list.txt 'http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'

# compile into single unique list
echo "[+] Cleaning up domains"
sed -e '/^$/d' -e '/^\#/d' -e 's/[^\s]*\s//' -i /tmp/ads-list.txt
sed -e '/^$/d' -e '/^\#/d' -i /tmp/mal-list.txt
sed -e '/^$/d' -e '/^\#/d' -i /tmp/ran-list.txt
cat /tmp/ads-list.txt /tmp/mal-list.txt /tmp/ran-list.txt | sort | uniq > /tmp/blacklist.txt

# supply the list of domain to squid as well
yes | rm -f /etc/squid/blocked_sites.txt
yes | cp -f /tmp/blacklist.txt /etc/squid/blocked_sites.txt

# zone "$DOMAIN" { type master; file "/var/named/named.blocked.zone.db"; };
echo "[+] Creating blacklisted config"
while read domain
do
        printf "zone \"%s\" { type master; file \"/var/named/named.blacklisted.zone.db\"; };\n" $domain >> /tmp/blacklisted.zones
done < /tmp/blacklist.txt

# cleanup
echo "[+] Cleaning up temp files"
rm -f /tmp/ads-list.txt
rm -f /tmp/mal-list.txt
rm -f /tmp/ran-list.txt
rm -f /tmp/blacklist.txt

#vi /var/named/chroot/var/named/named.blocked.zone.db
#$TTL    86400   ; one day
#@       IN      SOA     ns.local. hostmaster.ns.local.
#(
#               2014090101 ; serial
#                    28800 ; refresh
#                     7200 ; retry
#                   864000 ; expire
#                    86400 ; ttl
#)
#               NS      ns
#               A       127.0.0.1
#@      IN      A       127.0.0.1
#*      IN      A       127.0.0.1
#               AAAA    ::1
#*      IN      AAAA    ::1

# copy files to bind9 location
echo "[+] Copying created blacklist config"
yes | rm -f /var/named/chroot/etc/named.blacklisted.zones
yes | mv /tmp/blacklisted.zones /var/named/chroot/etc/named.blacklisted.zones

echo Done!
