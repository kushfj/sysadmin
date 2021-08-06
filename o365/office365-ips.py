#!/bin/python
"""
Description:
office365-ips parses the Microsoft Offic 365 URLs and IPs XML file and
generates separate XML file for each Offic 365 service to be used as an XML
external feed for Cisco WSA with Async OS 10.x and higher. The script also
generated configuration for Cisco ASA to create network objects and groups for
Office 365 services. The asa configuration may be manually pasted into the
Cisco ASA CLI. The script does not support IPv6 addresses.

TODO:
  * Implement more thorough input validation
  * Implement error checking
  * Implement access via web proxy

Revision control:
  * 0.1 - Initial version
  * 0.2 - Minor output formatting changes
"""

import os
import requests
import sys
import xml.etree.ElementTree as _xml
from netaddr import *


# Global variables
last_updated = ''
ipv6 = False
num_args = 0

# Define constants
# - https://support.content.office.net/en-us/static/O365IPAddresses.xml
url='https://go.microsoft.com/fwlink/?linkid=533185'
fname='tmp.xml'
asa_fname='asa_config.txt'
host_prefix='ext-ms-office365-'
net_prefix='ext-ms-office365-'
group_prefix='NO-GRP-OFFICE365-'
NEWLINE='\n'

# Parse arguments
num_args = len(sys.argv)
if num_args == 2:
  last_updated = sys.argv[1]
#elif num_args == 3:
#  last_updated = sys.argv[1]
#  ipv6 = sys.argv[2]
#  if ipv6 == 'Y' or ipv6 == '6' or ipv6 == 'ipv6':
#    ipv6 = True
else:
  print(sys.argv[0]+' <last_updated> [Y|6|ipv6]')
  print('where:')
  print('  last_updated - is the last updated date in the format M/D/YYYY')
  print('  Y|6|ipv6     - support IPv6 addresses')
  sys.exit('error: invalid arguments')


# Get the office 365 URLs and IPs XML file
resp = requests.get(url)
if requests.codes.ok == resp.status_code:
  with open(fname, 'wb') as f:
    f.write(resp.content)
  f.close()
else:
  sys.exit('error: cannot get - '+url)

# Parse the XML file
tree = _xml.parse(fname)
root = tree.getroot()
root_attribs = root.attrib
updated = root_attribs['updated']
if last_updated == updated:
  sys.exit('info: no need to update')
else:
  print('info: updating...')

config = open(asa_fname, 'w')
config.write('!'+NEWLINE)
config.write('! Last updated: '+updated+NEWLINE)
config.write('!'+NEWLINE)

for service in root:
  service_attribs = service.attrib
  service_name = service_attribs['name']

  new_service_root = _xml.Element('products')
  new_service_root.set('updated', str(updated))
  if not ipv6:
    new_service = _xml.Element('product')
    new_service.set('name', service_name)
    for addr_list in service:
      addr_list_attribs = addr_list.attrib
      if addr_list_attribs['type'] != 'IPv6':
        new_service.append(addr_list)

        # Generate ASA config
        if addr_list_attribs['type'] == 'IPv4':
          obj_list = []
          host_count = 1
          net_count = 1
          config.write('!'+NEWLINE)
          config.write('! Generating objects for '+service_name+NEWLINE)
          config.write('!'+NEWLINE)
          for addr in addr_list.iter('address'):
            cidr_ip_addr = addr.text
            #print('debug: cidr_ip_addr='+cidr_ip_addr)
            ip = IPNetwork(cidr_ip_addr)
            obj_name = ''
            if 1 == ip.size:
              obj_name = host_prefix+service_name+'-host'+str(host_count)
              host_count = host_count + 1
            else:
              obj_name = net_prefix+service_name+'-net'+str(net_count)
              net_count = net_count + 1
            #print('debug: object network '+str.lower(obj_name))
            #print('debug:   subnet '+str(ip.network)+' '+str(ip.netmask))
            config.write('!'+NEWLINE)
            config.write('! '+cidr_ip_addr+NEWLINE)
            config.write('object network '+str.lower(obj_name)+NEWLINE)
            config.write('  subnet '+str(ip.network)+' '+str(ip.netmask)+NEWLINE)
            obj_list.append(obj_name)

          group_name = str.upper(group_prefix+service_name)
          #print('debug: object-group network '+group_name)
          config.write('!'+NEWLINE)
          config.write('!'+NEWLINE)
          config.write('! Generating group for '+service_name+NEWLINE)
          config.write('!'+NEWLINE)
          config.write('object-group network '+group_name+NEWLINE)
          for obj in obj_list:
            #print('debug:   network-object object '+obj)
            config.write('  network-object object '+obj+NEWLINE)
    new_service_root.append(new_service)
  else:
    new_service_root.append(service)

  new_tree = _xml.ElementTree()
  new_tree._setroot(new_service_root)
  new_tree.write(service_name+'.xml', encoding='utf-8', xml_declaration=True, default_namespace=None, method='xml')

# Cleanup
config.flush()
config.close()
try:
  os.remove(fname)
except OSError:
  sys.exit('error: unable to delete file - '+fname)
