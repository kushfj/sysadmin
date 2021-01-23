#!/usr/bin/python3

# hash, size, created, modified, path

import hashlib
import os
import sys

BUFF_SIZE = 65535

path = sys.argv[1]

def gethash(file):
  sha1 = hashlib.sha1() 
  with open(file, 'rb', buffering=0) as f:
    while True:
      buff = f.read(BUFF_SIZE) 
      if not buff:
        break
      sha1.update(buff)
  return sha1.hexdigest()

print("hash,\tsize,\tctime,\tname")
for root, dirs, files in os.walk(path):
  for file in files:
    if os.path.exists(file):
      print("{hash},\t{size},\t{ctime},\t\"{name}\"".format(hash=gethash(file),size=os.path.getsize(file),ctime=os.path.getctime(file),name=os.path.join(root, file)))
