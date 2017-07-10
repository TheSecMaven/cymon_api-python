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
import datetime

config = ConfigParser()
config.read('config.ini')
token = config.get('DEFAULT', 'TOKEN')                          #Get API Key and Password from Config.INI file
proxies = config.get('DEFAULT','Proxies')
authuser = str(input('What is the username for Proxy Auth: '))
authpassword = getpass.getpass('Password for Proxy:')
auth = authuser + ":" + authpassword
proxies = {"https": 'http://' + authuser + ':' + authpassword + '@' + proxies}
engine = create_engine('sqlite:///v2/IP_Reportv2.db')   #Setup the Database
DBSession = sessionmaker(bind = engine)
session = DBSession()           #Must be able to query database
output = open('IPs/' + sys.argv[2]+".json","w")    #Output all downloaded json to a file

whois = ""
def send_request(apiurl, scanurl, headers,output):   #This function makes a request to the X-Force Exchange API using a specific URL and headers. 
    print (apiurl)
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
    if(input_string == 0):
        return 0
    else:
        columns = ["IP","Location","Date","Score","Category","registrar_name","registrar_organization"]
        columner1 = str(columns[column_number])
    
        input_current = session.query(IP_Current).filter(IP_Current.IP == Provided_IP).one()
        setattr(input_current,str(literal_column(str(columner1))),str(input_string))         #Update current table with new information
        session.commit()
    
        input_historic = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
        setattr(input_historic,str(literal_column(str(columner1))),str(input_string))   #Update historic table with new information
        session.commit()

def date_parse(date_string):                          #This function parses the date that comes from the raw JSON output and puts it in a Month/Day/Year format
    if(date_string == "none"):
        return 0
    else:
        parsed_date = dateutil.parser.parse(date_string).strftime("%x")
        return parsed_date

def get_current_info(column_number,review_count,Provided_IP,all_json):             #This function pulls current information from JSON output for a handful of keys
    tags = ""
    keys = ["tag","updated"]
    attr = keys[column_number]                              #Declarations
    key_count = 0
    current_info = ""

    if attr == "updated" and len(all_json['hits']) != 0:   #If the attribute we are looking for is the created date or score
        return all_json["hits"][0]['timestamp']
    if len(all_json['hits']) != 0:
        for tag in all_json['hits'][0]['tags']:
            tags += tag + ' '
        return tags
    else:
        return "none"


if __name__ == "__main__":
    Provided_IP = str(sys.argv[2])
    headers ={'Content-Type': 'application/json'}
    url = "https://api.cymon.io/v2/"
    apiurl = url + "/v2/auth/login"
    cymon_user = str(input('What is the username for Cymon v2: '))
    cymon_password = getpass.getpass('Password for Cymon Account:')
    post = {"username":cymon_user,"password":cymon_password}

    jwt = requests.post('https://api.cymon.io/v2/auth/login',proxies=proxies,data=json.dumps(post),headers=headers,verify=True)
    mytoken = jwt.json()
    jwt = mytoken['jwt']


    headers = {'Authorization': token}
    url = "https://api.cymon.io/v2/"


    parser = OptionParser()
    parser.add_option("-i", "--ip", dest="s_ip" , default="none",  #Use this option to check an IP address
                      help="ip to be checked on cymon", metavar="ipaddress")
    parser.add_option("--domain", "--domain", dest="s_domain" , default="none",
                      help="domain name to be checked on cymon", metavar="domain")                                           
(options, args) = parser.parse_args()

IP_exists = check_ip_exist(IP_Current,Provided_IP)              #Check if the IP provided exists in the table already. If so, they we don't need to create another entry
IP_exists_history = check_ip_exist(IP_History,Provided_IP)


if (options.s_ip is not "none"):    #If the -i option was used
	scanurl = options.s_ip
	apiurl = url + "/ioc/search/ip/" + scanurl + "?startDate=" + str((datetime.datetime.now() - datetime.timedelta(days=30)).strftime('%Y-%m-%d')) + '&endDate=' + str(datetime.datetime.now().strftime('%Y-%m-%d')) + '&from=0&size=3'
	domain_json = send_request(apiurl,scanurl,headers,output)
	if('errorMessage' in domain_json):
		print ("No IOCs Found for this IP. Please Try Again")
	else: 
		if(domain_json['total'] != 0):
		    IP_Location = str(domain_json["hits"][0]['location']['city']) + ',' + str(domain_json["hits"][0]['location']['country'])
		else:
		    IP_Location = "Unknown"
		print (domain_json)
		     #Used to hold categories of an IP or URL that have already been listed in the report.

		update_both_tables(1,IP_Location,Provided_IP)


		already_categorized=[]
		current_categories = ""
		key_count = 0                                           #Declarations
		category_count = 0
		review_count = 0
		update_both_tables(4,get_current_info(0,review_count,Provided_IP,domain_json),Provided_IP)             #Update Categorization of IP on Current Table   ***TO_DO*** (needs to only update current, not historic) ***TO_DO***
		update_both_tables(1,IP_Location,Provided_IP)
		review_count =0 
		for key in domain_json['hits']:    #For every entry in the json output 
			for tag in key['tags']:
				if(tag in already_categorized):                               #If this categorization has already been reported, don't report it again
					continue
				else:       #Since we already have this IP in our DB,
					update_historic_category = session.query(IP_History).filter(IP_History.IP == Provided_IP).one()
					if category_count == 0:    #If this is the first categorization that has been assigned to this IP
						update_historic_category.Category = str(tag)
						category_count += 1
					else:   #Otherwise we need commas and to keep what was already in there
						update_historic_category.Category = update_historic_category.Category + " , " + str(tag)
						category_count += 1 
						session.commit()
					already_categorized.append(tag)   #Add the category to the list of already printed categories so we don't repeat

		update_both_tables(2,date_parse(str(get_current_info(1,review_count,Provided_IP,domain_json))),Provided_IP)   #Adds the latest security check on this IP address to IP_Current Table information

		if (options.s_domain is not "none"):    #If the -i option was used
			scanurl = options.s_domain
			apiurl = url + "/ioc/search/domain/" + scanurl + "?startDate=" + str(datetime.datetime.today() - datetime.timedelta(days=7)) + '&endDate=' + str(datetime.datetime.today()) + '&from=0&size=3'
			domain_json = send_request(apiurl,scanurl,headers,output)
		if(domain_json['total'] != 0):
			IP_Location = str(domain_json["hits"]['location']['city']) + ',' + str(domain_json["hits"]['location']['country'])
		else:
			IP_Location = "Unknown"

		print (domain_json)
		print (IP_Location)

	
if len(sys.argv[1:]) == 0:
    parser.print_help()
