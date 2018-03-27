#!/usr/local/bin/python3

"""Interact with a linksys x6200 router

Tested on firmware 1.0.00 (019)
Author: Ben Formosa
"""

import argparse
import errno
import hashlib
import os
import re
import requests
import sys
from urllib.parse import urljoin

def en_value(data):
    """Encode data for passing to login form.

    The string data is padded to 64 characters and hashed.
    This is a port of en_value(data), from index.html on the router's web interface
    """

    pseed2 = ''
    buffer1 = data
    Length2 = len(data)

    # add another character or two
    if Length2 < 10:
        buffer1 += '0'
    buffer1 += str(Length2)

    Length2 += 2

    # fill pseed2 with charaters from buffer1 until pseed2 is 64 characters long
    for p in range(0,64):
        tempCount = p % Length2
        pseed2 += buffer1[tempCount:tempCount+1] 

    #return the md5 hash of pseed2
    b = bytearray()
    b.extend(map(ord, pseed2))
    m = hashlib.md5()
    m.update(b)
    return m.hexdigest()

def login(
        base_url,
        user,
        password
    ):
    """Login to the router and return session_key
    
    Raises:
        requests.exceptions.ConnectionError if connection to router fails
        ValueError if login fails
    """
    
    login_data = {
        'submit_button': 'login',
        'enc': '1',
        'origin_address': base_url,
        'user': user,
        'pwd': en_value(password),
    }

    # raises ConnectionError if connection to host fails
    r = requests.post(urljoin(base_url, 'login.cgi'), data=login_data)  
    pattern = re.compile(r"var session_key='\w+';")
    
    # search will be None if the login fails
    search = re.search(pattern, r.text)
    if(search):
        return search.group().split("'")[1]
    else:
        raise ValueError
    
def get_page(base_url, session_key, page):
    """GET a page"""
    r = requests.get(urljoin(base_url, page + ';session_id=' + session_key), stream=True)
    return r

def get_info(base_url, session_key):
    """Get data on the router's status"""
    info = {}
    r = get_page(base_url, session_key, 'Status_Router.asp')
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

def reconnect(base_url, session_key):
    """Request the router to reconnect"""

    data = {
        'change_action': 'gozila_cgi',
        'submit_type': 'start_wan',
        'submit_button': 'Status_Router',
        'session_key': session_key,
    }

    r = requests.post(urljoin(base_url, 'apply.cgi' + ';session_id=' + session_key), data=data)

def get_ip(base_url, session_key):
    """Get the IP address set on the router"""

    return get_info(base_url, session_key)['wan_ipaddr']

def check_ip(base_url, session_key):
    """Simple connection test

    Compare the router's IP to the result of whatismyipaddress.com
    Returns true if they match
    """

    router_ip = get_ip(base_url, session_key)
    remote_ip = requests.get('https://bot.whatismyipaddress.com/').text
    if(router_ip == remote_ip):
        print("Connection OK")
        return True
    else:
        print("Connection problem")
        return False

def main():
    """Handle argments, login to the router and exceptions"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-t',
        '--target',
        default='192.168.1.1',
        help="Hostname or IP address of router",
        metavar='HOSTNAME',
        type=str,
    )

    parser.add_argument(
        '-u',
        '--user',
        metavar='USER',
        type=str,
        default='admin',
        help="Name of admin user",
    )

    parser.add_argument(
        '-p',
        '--password',
        help="Password of admin user",
        metavar='PASSWORD',
        required=True,
        type=str,
    )

    parser.add_argument(
        'command',
        choices=[
            'info',
            'reconnect',
            'test'
        ],
        default='info',
        help='Command to run',
        metavar='COMMAND',
        nargs='?',
        type=str,
    )
    
    args = parser.parse_args()
    base_url = urljoin('http:', '//' + args.target + '/')
    
    try:
        session_key = login(base_url, args.user, args.password)
        
        if(args.command == 'info'):
            print(get_info(base_url, session_key))
        elif(args.command == 'reconnect'):
            reconnect(base_url, session_key)
            check_ip(base_url, session_key)
        elif(args.command == 'test'):
            check_ip(base_url, session_key)
    
    except requests.exceptions.ConnectionError:
        print('Connection to router failed, check the hostname or IP address',
            file=sys.stderr)
        sys.exit(errno.ECONNREFUSED)
    except ValueError:
        print('Login to router failed, check the username and password',
            file=sys.stderr)
        sys.exit(errno.EACCES)

if __name__ == '__main__':
    main()