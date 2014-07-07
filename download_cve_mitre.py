#!/usr/bin/env python

import os
import sys
import urllib

def main(argv):
  filename = "http://cve.mitre.org/data/downloads/allitems.xml"
  print "[*] Downloading '{}' to '{}'".format(filename, os.path.basename(filename))
  urllib.urlretrieve(filename, filename=os.path.basename(filename))
  return 0

if __name__ == "__main__":
  sys.exit(main(sys.argv))