#!/usr/bin/python3
#interact with a linksys x6200 router, firmware 1.0.00 (014)
#Ben Formosa
#2016-08-26

import hashlib
import re
import requests
from urllib.parse import urljoin

def en_value(data):
  """Encode data for passing to login form.
  The string data is padded to 64 characters and hashed.
  This is a port of en_value(data), from index.html on the router's web interface"""

  pseed2 = ''
  buffer1 = data
  Length2 = len(data)

  #add another character or two
  if Length2 < 10:
    buffer1 += '0'
  buffer1 += str(Length2)

  Length2 += 2

  #fill pseed2 with charaters from buffer1 until pseed2 is 64 characters long
  for p in range(0,64):
    tempCount = p % Length2
    pseed2 += buffer1[tempCount:tempCount+1] 

  #return the md5 hash of pseed2
  b = bytearray()
  b.extend(map(ord, pseed2))
  m = hashlib.md5()
  m.update(b)
  return m.hexdigest()

def get_session_key(login_data):
    r = requests.post(urljoin(base_url, 'login.cgi'), data=login_data)
    pattern = re.compile(r"var session_key='\w+';")
    return re.search(pattern, r.text).group().split("'")[1]

def get_status(session_id):
    r = requests.get(urljoin(base_url, 'Status_Router.asp' + session_id), stream=True)
    return r

def get_info(session_id):
    info = {}
    r = get_status(session_id)
    start_pattern = re.compile(r'ej.extend\(')
    end_pattern = re.compile(r'},')
    matching = False
    for l in r.iter_lines():
        line = l.decode()
        if re.search(start_pattern, line):
            matching = True
        if re.search(end_pattern, line):
            matching = False
        if matching:
            try:
                temp = re.split(r':\s', line)
                k = temp[0].strip()
                v = temp[1].split("'")[1].strip()
                info[k] = v
            except:
                pass
    return info

host = '192.168.1.1'
base_url = urljoin('http:', '//' + host + '/')
user = 'admin'
password = 'SECRET'
hashed_password = en_value(password)

login_data = {
  'submit_button': 'login',
  'keep_name': '1',
  'enc': '1',
  'origin_address': base_url,
  'user': user,
  'pwd': hashed_password,
  '_keep_name': 'on'
}

session_id = ';session_id=' + get_session_key(login_data)

#get_status(session_id)
print(get_info(session_id))

