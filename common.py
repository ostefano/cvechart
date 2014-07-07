import time
import re

from dateutil import parser
from datetime import datetime
from time import mktime

CRITERIA = {
  'criteria_1' : 0,
  'sink' : 1
}

VULNERABILITY = {
  'webc'     : 0,
  'stackc'   : 1,
  'heapc'    : 2,
  'intc'     : 3,
  'pointc'   : 4,
  'fmtc'     : 5,
  'otherc'   : 6,
  'sink'     : 7,
}

VERSION = 'v1.0'

LF = "\n"

LOG_LEVELS = {
  'critical'     :       1,
  'error'        :       2,
  'warning'      :       3,
  'info'         :       4,
  'debug'        :       5
}

CONF = {
  'LOG_LEVEL' : 'debug',
}

def log(level, line, isFormatted=1):
  global LF, LOG_LEVELS, CONF
  if level not in LOG_LEVELS:
    level = 'error'   
  if LOG_LEVELS[level] <= LOG_LEVELS[CONF['LOG_LEVEL']]:
    if isFormatted:
      line = '[%s] %s%s' % (level, line, LF)
    else:
      line = '%s%s' % (line, LF)
    sys.stderr.write(line)

def to_date(quarter):
  a = quarter.split("Q")
  y = int(a[0])
  q = int(a[1])
  if q == 1:
    q = 3
  elif q == 2:
    q = 6
  elif q == 3:
    q = 9
  else:
    q = 12
  return str(y)+"-"+str(q)

def generate_quarters(start_year, start_q, end_year, end_q):
  quarters = []
  current_year = start_year
  current_q = start_q
  while current_year <= end_year:
    if current_year == end_year:
      lim_eq = end_q
    else:
      lim_eq = 4
    while current_q <= lim_eq:
      quarters.append(str(current_year) + "Q" + str(current_q))
      current_q += 1
    current_q = 1
    current_year += 1 
  return quarters

def timestamp():
  now = time.time()
  localtime = time.localtime(now)
  return time.strftime('%Y%m%d', localtime)

def get_criteria_one(desc):
  criteria_one  = re.compile('use[- ]after[- ]free|dangling', re.IGNORECASE)
  if criteria_one.search(desc):
    return CRITERIA['criteria_1']

  return CRITERIA['sink']

def get_statistics(desc):
  webc   = re.compile('php|sql|xss', re.IGNORECASE)
  if webc.search(desc):
    return VULNERABILITY['webc']
  
  stackc = re.compile('stack-based|stack overflow', re.IGNORECASE)
  if stackc.search(desc):
    return VULNERABILITY['stackc']

  heapc  = re.compile('heap-based|heap overflow|use[- ]after[- ]free|double free', re.IGNORECASE)
  if heapc.search(desc):
    return VULNERABILITY['heapc']

  intc   = re.compile('integer|signedness|off[- ]by[- ]one', re.IGNORECASE)
  if intc.search(desc):
    return VULNERABILITY['intc']

  pointc = re.compile('dereference|dangling pointer', re.IGNORECASE)
  if pointc.search(desc):
    return VULNERABILITY['pointc']

  fmtc   = re.compile('format string', re.IGNORECASE)
  if fmtc.search(desc):
    return VULNERABILITY['fmtc']

  otherc = re.compile('overflow', re.IGNORECASE)
  if otherc.search(desc):
    return VULNERABILITY['otherc']

  return VULNERABILITY['sink']

class DataFileWriter:

  def __init__(self, dataFileName):
    self.dataFile = open(dataFileName, 'w')
    self.dataFile.truncate()

  def append(self, line):
    global LF
    self.dataFile.write(line + LF)

  def write_histogram(self, x, y):
    global LF
    assert(len(x) == len(y))
    for i in range(len(x)):
      self.dataFile.write(str(x[i]) + "\t" + str(y[i]) + LF)

  def close(self):
    self.dataFile.close()