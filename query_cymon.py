#!/az/arcsight/counteract_scripts/env/bin/python
#Miclain Keffeler
#6/8/2017 
__author__ = 'mkkeffeler'
import requests
import sys
import json
from sqlalchemy import create_engine
from sqlalchemy.sql.expression import literal_column
from sqlalchemy.orm import sessionmaker
from sqlalchemy import types
from sqlalchemy import Column, Text, ForeignKey, Integer, String
from optparse import OptionParser
import hashlib
import base64
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
#from build_database import IP_Current, IP_History
from sqlalchemy import exists
import dateutil.parser
from sqlalchemy.sql.expression import literal_column
from configparser import ConfigParser
import urllib
import getpass
import os
Event_ID = str(sys.argv[1])     #Event ID being passed in same placea
my_ip = "None"   #For Global IP address 

def key_reader(): #Reads the .keynum file to determine which key is next to be used in list of 5 keys 
    my_num = 0
    with open(os.path.join(os.path.dirname(__file__), '.keynum')) as f:
        lines = f.readlines()
        for line in lines:
            my_num = line[0]
    return my_num

def key_writer(my_key): #Writes the newest key number to be used in the next run of this script
    with open(os.path.join(os.path.dirname(__file__), '.keynum'),'w') as f:
        if(my_key == 6):
            f.write('1')
        else:
            f.write(str(my_key))
        f.close()

def get_key(key_num): #Used to open and pull the actual token used to authenticate with Cymon
    my_token = ""
    with open(os.path.join(os.path.dirname(__file__),('.key' + key_num))) as f:
        lines = f.readlines()
        for line in lines:
            my_token = line.strip()
    return my_token

def optional_arg(arg_default,Event_ID): #Gets called as a callback action when -h option (hostname) is used. Will return 1 of 2 things based on the presence of a hostname
    def func(option,opt_str,value,parser):
        if parser.rargs == []:
            print ("Hostname Results: None")
        else:
            global my_domain
            my_domain = parser.rargs[0]
    return func

def confirm_validity_of_token(token): #Confirms that a token was correctly provided and fits general format
    if 'Token' not in token:
        print ("Event ID: " + Event_ID)
        print ("Domain Name: Unknown")
        print ("Token is not valid. Please check the variation of token you are using")
        key_writer(int(key_reader())+1)
        exit()

def optional_arg2(arg_default,Event_ID): #Confirms the presence or lack of an IP address in -i option. 
    def func(option,opt_str,value,parser):   #Function to hold parser data
        if len(parser.rargs) ==  0:
            print ("Domain Name: Unknown")
            exit()
        else:
            global my_ip
            my_ip = parser.rargs[0]
    return func

def send_request(apiurl, scanurl, headers,output):   #This function makes a request to the X-Force Exchange API using a specific URL and headers. 
    response = requests.get(apiurl, params='',proxies=proxies, headers=headers,timeout=20)
    all_json = response.json()
    output.write(json.dumps(all_json,indent=4,sort_keys=True))
    return all_json

def get_md5(filename):     #This function returns the MD5 hash of a provided file
    try:
        f = open(filename,"rb")
        md5 = hashlib.md5((f).read()).hexdigest()
        return md5
    except e:
        print (str(e))
		

def check_ip_exist(Table,Provided_IP):           #This function confirms whether or not an entry already exists. If so, it returns the entry 
    while(1):
        count = session.query(Table).filter(Table.IP == Provided_IP).count()  
        if count > 0:               #If the entry for this IP exists already (There is 1 occurence of this IP in the table)
            return session.query(Table).filter(Table.IP == Provided_IP).one()
        else:
            new_IP = Table(IP = Provided_IP)
            session.add(new_IP)
            session.commit()
            return 0

def update_both_tables(column_number,input_string,Provided_IP):              #This function will update both current and historic tables for a given column
    columns = ["IP","Location","Date","Score","Category","registrar_name","registrar_organization"]
    columner1 = str(columns[column_number])
    
    input_current = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
    setattr(input_current,str(literal_column(str(columner1))),str(input_string))         #Update current table with new information
    session.commit()
    if(str(columner1) == 'Location'):
        print ('Domain Name: ' + input_string)
    elif(str(columner1) == 'Category'):
        print ('Current Categorizations: ' + input_string)
    else:
        print (str(columner1) + ": " + input_string)
    input_historic = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
    setattr(input_historic,str(literal_column(str(columner1))),str(input_string))   #Update historic table with new information
    session.commit()

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    parsed_date = dateutil.parser.parse(date_string).strftime("%x")
    return parsed_date

def get_current_info(column_number,review_count,Provided_IP,all_json):             #This function pulls current information from JSON output for a handful of keys
     
    keys = ["tag","updated"]
    attr = keys[column_number]                              #Declarations
    key_count = 0
    current_info = ""

    if attr == "updated":   #If the attribute we are looking for is the created date or score
        return all_json["results"][0][attr]
    else:
        return all_json["results"][0][attr]  #For every report except the most recent report (Which is current, not history)



config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))
token = config.get('DEFAULT', 'TOKEN')                          #Get API Key and Password from Config.INI file
proxies = config.get('DEFAULT','Proxies')   #Check for proxy settings if applicable
if(proxies == ""):
    auth = ""
else:
    proxies = {"https": 'http://' +  proxies}

engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
output = open(os.path.join(os.path.dirname(__file__), 'IPs/') + 'latestv1.json','w')

#Python option parser implementation
parser = OptionParser()

parser.add_option("-i", "--ip",action='callback', dest="s_ip" , default="none",
                      help="ip to be checked on cymon",callback=optional_arg2('empty',Event_ID), metavar="ipaddress")                                           #Use this option to check an IP address
parser.add_option("-t", "--hostname",action='callback', dest="s_hostname" , default="none",                                                   #-h still under development
                      help="hostname to be checked on cymon",callback=optional_arg('empty',Event_ID), metavar="hostname") 
parser.add_option("-1", "--1key",action='store_true',dest="is1key" , default=False,
                      help="If specified, this will set the token used for authentication to come from the config.ini file",metavar="hostname") #Used to specify how the script pulls keys
parser.add_option("-u", "--user", dest="user_name" , default=None,
                      help="Proxy Auth User Name", metavar="user")         #-u and -p are for proxy authentication when it is required
parser.add_option("-p", "--password", dest="password", default=None,
                      help="Proxy Auth Password", metavar="passss")
(options, args) = parser.parse_args()

#If we are only using 1 api key specified in config file
if(options.is1key == True):
    token = config.get('DEFAULT','TOKEN')
else:  #Otherwsie, we will be getting our key from the .key1_.5 files. Check for validity
    token = get_key(key_reader())     
confirm_validity_of_token(token) 
key_writer(int(key_reader()) + 1)           #Get API Key and Password from Config.INI file

if __name__ == "__main__":
    Event_ID = str(sys.argv[1])

    headers = {'Authorization': token}
    url = "https://cymon.io"

    Provided_IP = my_ip
    
    if(my_ip == ""):  #If no IP is specified
        print ("Domain Name: Unknown")
        exit()
    scanurl = my_ip
    apiurl = url + "/api/nexus/v1/ip/" + scanurl + "/events/"
    all_json = send_request(apiurl, scanurl, headers,output)    #Get event and domain name information on IP specified from Cymon
    apiurl = url + '/api/nexus/v1/ip/' + scanurl + '/domains/'
    domain_json = send_request(apiurl,scanurl,headers,output)
    
    if(domain_json['count'] != 0):   #If we have results 
        IP_Location = domain_json["results"][0]['name']
    else:  #Cymon didn't have anything on location
        IP_Location = "Unknown"
#Used to hold categories of an IP or URL that have already been listed in the report.
#update_both_tables(1,IP_Location,Provided_IP)
if(domain_json['count']>0):
    already_categorized=[]
    current_categories = ""
    historic_categories = ""
    key_count = 0                                           #Declarations
    category_count = 0
    review_count = 0
    domain_flag=0
    domain_name = ""
    for key in all_json['results']:    #For every entry in the json output 
        if(key['tag'] in already_categorized):                               #If this categorization has already been reported, don't report it again
            continue

        else:       #Since we already have this IP in our DB,
                
             
            if category_count == 0:    #If this is the first categorization that has been assigned to this IP
                historic_categories = str(key['tag'])
                category_count += 1
            else:   #Otherwise we need commas and to keep what was already in there
                historic_categories = historic_categories + " , " + str(key['tag'])
                category_count += 1 
            session.commit()

            already_categorized.append(key['tag'])   #Add the category to the list of already printed categories so we don't repeat
    
    print ('Domain Name: ' + IP_Location)
    print ('All Historical Categorizations: ' + historic_categories)
    print ("Total Reports on this IP: " + str(all_json['count']))
else:  #If no results were obtained
   print ("Domain Name: " + IP_Location)
   print ('No reports found for this IP')
if len(sys.argv[1:]) == 0:
    parser.print_help()
