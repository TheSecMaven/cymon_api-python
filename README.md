
# Cymon API
Cymon is the largest tracker and aggregator of security reports. This repository aims to easily utilize and incorporate the tools they provide within existing SIEM software as well as Information Security Departments.

# How to Use the Pull_Feeds Subdirectory
## pull_recent.py Usage
This  will pull a feed holding the most recent events/malware/urls sent to cymon. This script can be automated to run at set intervals. There is a file named ".namelastcall" that is used to store the filename of events pulled the last time the script was run. It is used to confirm we are not double sending the same IPs, URLs, or Domains that were in the last run.  <br> `python pull_recent.py` <br><br>

### Optional Proxy Auth in pull_recent.py
If needing to authenticate with proxy, simply add the proxy settings to config.ini file in directory above and it will prompt for credentials.

## query_cymon_api.py
This is used to query the cymon api and pull all relevant information regarding a specific IP/URL/File. Currently, it is only setup for IP addresses. To get a list of all possible arguments run <br>
`python query_cymon.py --help` and a list of all options with descriptions of each will appear. 
<br> 
### Notes
The script can handle when an IP address is not supplied. For example, the -i option can be used, but if it does not have an IP address following it then the script will return none for results. 
<br> 
### Optional Proxy Auth and Token usage in query_cymon.py
If needing to authenticate to proxy, simply add the proxy settings to config.ini file and script will use the credentials provided in -u and -p options to authenticate with proxy. -u <USERNAME> -p <PASSWORD><br><br>
If you want to use the Token specified in the config.ini file, rather than iterate over 5 keys specified in .key1->5 evenly. It decides which key to use based on the number specified in .keynum, which is changed automatically every call to query_cymon.py. Please provide the -1 or --1key flags in your call to query_cymon.py to make the token used come strictly from config.ini
### Usage
` python query_cymon.py <EVENT_ID> -i <IP_ADDRESS>`<br>
`python query_cymon.py <EVENT_ID> -u <USERNAME> -p <PASSWORD> -i <IP_ADDRESS>`<br>
***The -i option must always be defined as the last argument provided in the usage to ensure no errors, including the -1 or --1key flags. Working on a fix for this.  ***<br> 
<br>
## query_cymon_api_whois.py Usage
This will do the same thing that `query_cymon_api.py` does but it will also pull WHOIS information from the X-Force API.** Be sure to enter you're X-Force Key and Password as well as your Cymon Key when running. **<br>
`python query_cymon_api_whois.py -i <IP>`<br><br>
# Important Notes
**The database is capable of handling only the query_cymon_api.py script** To use the database with WHOIS information please proceed to the subdirectory `/whois`. 

# What's Next
Still working on integration within a database. Ability to query and store URL information as well as File hashes is being worked on. Ability to generate a CEF event upon a change within the database is also coming. 

# More to Come!
