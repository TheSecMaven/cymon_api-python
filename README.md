# Cymon API 
Cymon is the largest tracker and aggregator of security reports. This repository aims to easily utilize and incorporate the tools they provide within existing SIEM software as well as Information Security Departments.

# How to Use
## pull_recent.py
This  will pull a feed holding the most recent events/malware/urls sent to cymon. This can be setup to pull the latest feed every hour which could be used to check specific IPs or event types so that if a match is found you are notified that this is a known malicious IP/Virus/URL according to cymon. 

## query_cymon_api.py
This is used to query the cymon api and pull all relevant information regarding a specific IP/URL/File. Currently, it is only setup for IP addresses. Any categorizations that cymon or one of its sources replys back with is going to be sent to a database of scanned IPs. This can be used to monitor changes in internal IPs or to maintain an accurate blacklist, amongst many other examples. 

# What's Next
Still working on integration within a database. Ability to query and store URL information as well as File hashes is being worked on. Ability to generate a CEF event upon a change within the database is also coming. 

# More to Come!
