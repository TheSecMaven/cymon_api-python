#!/usr/bin/python

__author__='mkkeffeler'
#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime
import dateutil.parser
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
import os
from configparser import ConfigParser
import getpass
import codecs

def dynamic_event_names(category):   #Names the event based on what it is
    if(category == 'recent_domains'):
        return 'Known Malicious Domain'
    if(category == 'recent_ips'):
        return 'Known Malicious IP'
    if(category == 'recent_urls'):
        return 'Known Malicious URL'

def which_field(category):           #Used to specify a cef custom field based on what information is being pulled
    if(category == 'recent_domains'):
        return '|shost='
    if(category == 'recent_ips'):
        return '|src='
    if(category == 'recent_urls'):
        return '|request='

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%b %d %Y %H:%M:%S")
    return parsed_date
    f = codecs.open('test', encoding='utf-8', mode='w+')


def generate_cef_event(category,to_be_blacklisted,updated_time):   #Called from other scripts to compile and completely generate the text for cef event
    message = ""
    event_name = str(dynamic_event_names(category))
    message = "Blacklisted Item: " + str(codecs.decode(to_be_blacklisted,'unicode_escape').replace('=', '\\=')) + " Updated: " + str(date_parse(updated_time)) 
    cef = 'CEF:0|Cymon|Cymon API|1.0|100|' + event_name + '|1' + which_field(category) + str(codecs.decode(to_be_blacklisted,'unicode_escape').replace('=', '\\=')) + ' end='+ str(date_parse(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))) +' msg=' + message
    return cef
