#!/usr/bin/python

__author__='mkkeffeler'
#Miclain Keffeler
#6/6/2017
#This script holds the function needed to generate a CEF (Common Event Format) Event. 
#This can be called when a change is detected between historic and current data.
#A CEF event will then be generated and this can be fed to SIEM software such as HP Arcsight.
import datetime


def dynamic_event_names(category):
    if(category == 'recent_domains'):
        return 'Known Malicious Domain'
    if(category == 'recent_ips'):
        return 'Known Malicious IP'
    if(category == 'recent_urls'):
        return 'Known Malicious URL'


def generate_cef_event(category,to_be_blacklisted,updated_time):
    message = ""
    event_name = str(dynamic_event_names(category)
    message += 
    cef = 'CEF:0|X-Force|X-Force API|1.0|1.0|' + event_name + '|' + str(dynamic_priority(did_change(old_location,new_location),did_change(old_registrar_org,new_registrar_org),did_change(old_category,new_category),did_change(old_score,new_score),old_score,new_score,count_categories(new_category),count_categories(old_category))) + '|src= ' + str(IP_Address)+ ' end='+ str(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S:%fZ')) +' msg=' + message
    return cef
