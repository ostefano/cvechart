#!/usr/bin/env python

import os
import sys
import urllib
from datetime import datetime

def main(argv):
  
  s_year = 2003;
  e_year = datetime.now().year + 1;
  r_year = range(s_year, e_year);

  filenames = []
  for year in r_year:
    filenames.append("http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-" + str(year) + ".xml");

  for filename in filenames:
    print "[*] Downloading '{}' to '{}'".format(filename, os.path.basename(filename))
    urllib.urlretrieve(filename, filename=os.path.basename(filename))

  return 0

if __name__ == "__main__":
  sys.exit(main(sys.argv))
