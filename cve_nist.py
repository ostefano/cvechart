#!/usr/bin/env python

import re
import urlparse
import fileinput
import os
import sys
import time

from dateutil import parser
from datetime import datetime
from time import mktime

from xml.sax.handler import ContentHandler
from xml.sax import parse

from common import CRITERIA, VULNERABILITY
from common import log, to_date, get_statistics, get_criteria_one
from common import DataFileWriter

statistics = {}
statistics_compare = {}

class MyContentHandler(ContentHandler):

  def __init__(self):
    ContentHandler.__init__(self)
    self.seqs = []
    self.date = []
    self.desc = []
    self.index = 0

    self.indate = False
    self.indesc = False

    self.result_criteria_one = 0

  def startElement(self, name, attrs):
    if name == "entry":
      #print "entry"
      self.seqs.append(attrs.getValue("id"))

    if name == "vuln:published-datetime":
      #print "date"
      self.indate = True

    if name == "vuln:summary":
      #print "summ"
      self.indesc = True

  def endElement(self, name):

    if name == "vuln:published-datetime":
      self.indate = False

    if name == "vuln:summary":
      self.index += 1

      
      self.indesc = False

      if len(self.date) > 1:
        print self.date
        del self.date[-1]
        raw_input("analyze pls")
      
      assert len(self.seqs) == 1
      assert len(self.date) == 1
      assert len(self.desc) == 1

      seqs = self.seqs.pop()
      date = self.date.pop()
      desc = self.desc.pop()

      quarter = get_quarter(date)

      stat = get_statistics(desc)
      stat_criteria = get_criteria_one(desc)

      if not statistics.has_key(quarter):
        statistics[quarter] = []
        for i in range(len(VULNERABILITY)):
          statistics[quarter].append(0)
      statistics[quarter][stat] += 1

      if not statistics_compare.has_key(quarter):
        statistics_compare[quarter] = []
        for i in range(len(CRITERIA)):
          statistics_compare[quarter].append(0)
      statistics_compare[quarter][stat_criteria] += 1

      print "[{}] {} [{},{}] - {} - {}".format(self.index, quarter, seqs,date, statistics[quarter], statistics_compare[quarter])
      #raw_input("test")

  def characters(self, data):
    if self.indate:
      #print "date read"
      if len(self.date) == 1:
        old_date = self.date.pop()
        data = old_date + data
      self.date.append(data)

    if self.indesc:
      #print "desc read"
      if len(self.desc) == 1:
        old_data = self.desc.pop()
        data = old_data + data
      self.desc.append(data)

def get_quarter(date):
  d1 = time.strptime(date[:10], "%Y-%m-%d")
  d2 = datetime.fromtimestamp(mktime(d1))
  current_year = d2.year
  if d2.month <= 3:
    current_q = 1
  elif d2.month <= 6:
    current_q = 2
  elif d2.month <= 9:
    current_q = 3
  else:
    current_q = 4
  return str(current_year) + "Q" + str(current_q)

def main(argv):
  filename_1 = "cve_nist.dat"
  filename_2 = "cve_nist_criteria.dat"

  file_1 = DataFileWriter(filename_1)
  file_2 = DataFileWriter(filename_2)

  s_year = 2003;
  e_year = datetime.now().year + 1;
  r_year = range(s_year, e_year);

  input_file = []
  for year in r_year:
    input_file.append("nvdcve-2.0-" + str(year) + ".xml");

  for f in input_file:
    print "[*] Analyzing file: {}".format(f)
    handler = MyContentHandler()
    parse(f, handler)

  for k in sorted(statistics.keys()):
    v = statistics[k]
    v2 = statistics_compare[k]
    line_1 = []
    line_2 = []

    date = to_date(k)
    
    use_after = v2[CRITERIA['criteria_1']]

    stackc = v[VULNERABILITY['stackc']]
    heapc = v[VULNERABILITY['heapc']] 
    intc = v[VULNERABILITY['intc']] 
    pointc = v[VULNERABILITY['pointc']] 
    fmtc = v[VULNERABILITY['fmtc']] 
    otherc = v[VULNERABILITY['otherc']]
    total = stackc + heapc + intc + pointc + fmtc + otherc

    if total == 0:
      percentage = 0
    else:
      percentage = (float(use_after) / float(total)) * float(100)

    line_1.append(str(date))
    line_1.append(str(stackc))
    line_1.append(str(heapc))
    line_1.append(str(intc))
    line_1.append(str(pointc))
    line_1.append(str(fmtc))
    line_1.append(str(otherc))
    line_1.append(str(total))

    line_2.append(str(date))
    line_2.append(str(use_after))
    line_2.append(str(total))
    line_2.append(str(percentage))

    file_1.append("\t".join(line_1))
    file_2.append("\t".join(line_2))

    print "{} - {} <-> {} <-> {}".format(k,v, v2, percentage)

  file_1.close()
  file_2.close()

  return 0

# ENTRY POINT
if __name__ == "__main__":
  sys.exit(main(sys.argv))
