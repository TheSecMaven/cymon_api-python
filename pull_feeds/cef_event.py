#!/usr/bin/python

__author__='mkkeffeler'
#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime
import dateutil.parser

def dynamic_event_names(category):
    if(category == 'recent_domains'):
        return 'Known Malicious Domain'
    if(category == 'recent_ips'):
        return 'Known Malicious IP'
    if(category == 'recent_urls'):
        return 'Known Malicious URL'

def which_field(category):
    if(category == 'recent_domains'):
        return '|shost='
    if(category == 'recent_ips'):
        return '|src='
    if(category == 'recent_urls'):
        return '|request='

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%b %d %Y %H:%M:%S")
    return parsed_date



def generate_cef_event(category,to_be_blacklisted,updated_time):
    message = ""
    event_name = str(dynamic_event_names(category))
    message = "Blacklisted Item: " + str(to_be_blacklisted) + " Updated: " + str(date_parse(updated_time)) 
    cef = 'CEF:0|Cymon|Cymon API|1.0|100|' + event_name + '|1' + which_field(category) + str(to_be_blacklisted)+ ' end='+ str(date_parse(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))) +' msg=' + message
    return cef
