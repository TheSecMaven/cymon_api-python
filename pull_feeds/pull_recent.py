#Miclain Keffeler
#6/8/2017
#This script pulls the most recent events/malware/URLs that have been submitted as suspicious or malicious from cymon.io. Eventually this information will be automatically parsed and stored so that if a new malware tried to enter a network it could be searched quickly in this up-to-date table and potentially stopped from entering. 
import os
import requests
import json
import datetime
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from optparse import OptionParser
import hashlib
import base64
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column
from configparser import ConfigParser
import urllib
import getpass

config = ConfigParser()
config.read('../config.ini')
token = config.get('DEFAULT', 'TOKEN')                          #Get API Key and Password from Config.INI file
proxies = config.get('DEFAULT','Proxies')
if(proxies == ""):
    auth = ""
else:
    #TODO need to change from hardcoded arg indexes
    authuser = str(input('What is the username for Proxy Auth: '))
    authpassword =getpass.getpass('Password for Proxy:')
    auth = authuser + ":" + authpassword
    proxies = {"https": 'http://' + authuser + ':' + authpassword + '@' + proxies}


filename = "recent_feed-" + str(datetime.datetime.now().strftime('%FT%TZ')) + ".json"
output = open(filename,"w")
link = "https://cymon.io/api/dashboard/v1/recent-objects/"
response1 = ""
if(proxies == ""):
    response = requests.get(link,headers = {'Authorization': token,'content-type':"application/json"})
all_json = response.json()
output.write(json.dumps(all_json,indent=4,sort_keys=True))
os.system('python3 submit_events.py ' + filename)

