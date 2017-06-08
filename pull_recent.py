#Miclain Keffeler
#6/8/2017
#This script pulls the most recent events/malware/URLs that have been submitted as suspicious or malicious from cymon.io. Eventually this information will be automatically parsed and stored so that if a new malware tried to enter a network it could be searched quickly in this up-to-date table and potentially stopped from entering. 
import os
import requests
import json
import datetime

filename = "recent_feed-" + str(datetime.datetime.now().strftime('%FT%TZ')) + ".json"
output = open("/home/pi/cymon_api-python/feeds/"+filename,"w")
link = "https://cymon.io/api/dashboard/v1/recent-objects/"
response1 = ""
response = requests.get(link,headers = {'Authorization': "mkkeffeler Keff4450",'content-type':"application/json"})
all_json = response.json()
output.write(json.dumps(all_json,indent=4,sort_keys=True))

