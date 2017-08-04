#Miclain Keffeler
#6/8/2017 
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
from build_database import IP_Current, IP_History
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
authuser = str(input('What is the username for Proxy Auth: '))
authpassword = str(getpass.getpass('Password for Proxy:'))
auth = authuser + ":" + authpassword
if(proxies == ""):
    auth = ""
else:
    #TODO need to change from hardcoded arg indexes
    auth = authuser + ":" + authpassword
    proxies = {"https": 'http://' + authuser + ':' + authpassword + '@' + proxies}

engine = create_engine('sqlite:///IP_Report.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
output = open(sys.argv[2]+"v2.json","w")    #Output all downloaded json to a file

whois = ""
def send_request(apiurl, scanurl, headers,output):   #This function makes a request to the X-Force Exchange API using a specific URL and headers. 
    print (apiurl) 
    if(proxies == ""):
        response = requests.get(apiurl, params='', headers=headers,timeout=20)
    else:
        response = requests.get(apiurl, proxies=proxies, params='', headers=headers,timeout=20,verify=True)
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

if __name__ == "__main__":
    headers ={'Content-Type': 'application/json'}
    url = "https://api.cymon.io/v2"
    apiurl = url + "/v2/auth/login"
    cymon_user = str(input('What is the username for Cymon v2: '))
    cymon_password = getpass.getpass('Password for Cymon Account:')
    post = {"username":cymon_user,"password":cymon_password}

    jwt = requests.post('https://api.cymon.io/v2/auth/login',proxies=proxies,data=json.dumps(post),headers=headers,verify=True)
    mytoken = jwt.json()
    jwt = str(mytoken['jwt']) + " "
    print (mytoken)
    parser = OptionParser()
    parser.add_option("--pull", "--pull", dest="s_category" , default="none",
                      help="Categories that can be pulled: malware,botnet,spam,phishing,malicious activity(must be in \"),blacklist, and dnsbl", metavar="listname")                                           #Use this option to check an IP addres
parser.add_option("--max", "--max", dest="s_max" , default="none",
                      help="Max number of IPs to be returned", metavar="max") 

(options, args) = parser.parse_args()


if len(sys.argv[1:]) == 0:
    parser.print_help()


if (options.s_category is not "none"):
        scanurl = ""
        headers={'Authorization':'mkkeffeler ' + str(jwt)}
        category = str(options.s_category)                         #Categories that can be queried: malware, botnet,spam,phishing,malicious activity, blacklist, and dnsbl
        apiurl = url + "/query/tags/" + category
        all_json = send_request(apiurl,category+scanurl,headers,output)

for IP in all_json['results']:            #Will eventually store addresses
    print (IP['addr'])

