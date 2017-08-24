#!/usr/bin/python
__author__='mkkeffeler'

#Miclain Keffeler
#G6/6/2017 
#This script will update all the entries in both historic and current tables. Pulls the latest JSON file on every IP that is already in tables, and updates entries for that IP and continues for all.
import requests
import sys
import json
from optparse import OptionParser
import hashlib
import base64
import socket
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column
from cef_event import generate_cef_event
import os
from configparser import ConfigParser
import getpass
import codecs
import datetime

config = ConfigParser()
config.read('../config.ini')
HOST= config.get('DEFAULT', 'HOST')                          #Get Hostname and Port to send CEF event to from Config.INI file
PORT= config.get('DEFAULT', 'PORT')
Token = config.get('DEFAULT', 'TOKEN')                          #Get API Key and Password from Config.INI file
proxies = config.get('DEFAULT','Proxies')

filename = sys.argv[1]
print (filename)


if(proxies == ""):  #If proxy was specified
    auth = ""
else:
    #TODO need to change from hardcoded arg indexes
    proxies = {"https": 'http://' + proxies}

def which_field(category):   #Get appropriate json key based on what we are looking at now
    if(category == 'recent_domains'):
        return 'name'
    if(category == 'recent_ips'):
        return 'addr'
    if(category == 'recent_urls'):
        return 'location'

engine = create_engine('sqlite:///IP_Report.db')
DBSession = sessionmaker(bind = engine)
session = DBSession()

CONFIG = {}

def syslog(message, level=5, facility=5, host=HOST, port=int(PORT)):  #Sends generated cef event to provided host and port in config.ini
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '<%d>%s' % (level + facility*8, message)
        sock.sendto(data.encode(), (host, (port)))
        sock.close()

CONFIG['FACILITY'] = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

CONFIG['LEVEL'] = {
        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

event_types = ['recent_domains','recent_ips','recent_urls']

def date_parse(date_string):          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format

    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date


if __name__ == "__main__":
    CONFIG= {}
    CONFIG['FACILITY'] = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

    CONFIG['LEVEL'] = {
        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}  

    all_json = json.load(open(filename,'r'))    #Load the file

    for category in event_types:
        feed_data = all_json['data'][category]
        print (category)
        for entry in feed_data:   #Generate events for all entries
            event = generate_cef_event(category,entry[which_field(category)],entry['updated'])
            syslog(event)
            print(event)
 
    print ("All Events Pushed")
