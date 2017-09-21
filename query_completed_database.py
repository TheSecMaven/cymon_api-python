#Miclain Keffeler
#6/6/2017
#This script queries the database and pulls all information on a provided IP address, both current and historic, and displays it
__author__='mkkeffeler'
from build_database import IP_Current, IP_History
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from optparse import OptionParser
import sys
engine = create_engine('sqlite:///pull_feeds/IP_Report.db')
Base = declarative_base()
Base.metadata.bind = engine
from sqlalchemy.orm import sessionmaker
DBSession = sessionmaker(bind = engine)
DBSession.bind = engine
session = DBSession()

# Make a query to find all Persons in the database

columns = ["IP","Location","Date","Score","Category"]
# Retrieve one Address whose person field is point to the person object
# Return the first IP address from all the IP addresses in this table
def print_registrar_name(string):   #Print registrar name of IP address
    print "Registrar Name: " + str(string)

def print_registrar_org(string):  #print the registered organization of the IP address
    print "Registrar Organization: " + str(string)

def print_ip(string):   #This function is used to print the IP address
    print "IP: " + str(string)

def print_location(string):  #This function is used to print the IP location
    print "Location: " + str(string)

def print_date(string):   #This function is used to print the date of review
    print "Date of Review: " + str(string)

def print_score(string):    #This function is used to print the current or historic score of an IP
    print "Score: " + str(string)

def print_category(string):   #This function is used to print the current categorizations of an IP
    print "All Current Categorizations: " + str(string)

def print_historic_category(string):  #This function is used to print the historic categorizations of an IP
    print "All Historic Categorizations: " + str(string)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--all1", "--all", dest="all1", default="none",  
                      help="Print all elements of a provided IP", metavar="all")         #Prints all elements of the provided IP address
(options, args) = parser.parse_args()

if options.all1 is not "None":   #Only flag that is available

    person = session.query(IP_Current).filter(IP_Current.IP == options.all1).one()
    print "Current Information"                      #Print all the information on this IP in the current data table
    print_ip(person.IP)
    print_location(person.Location)
    print_date( person.Date)
    print_score( person.Score)
    print_category( person.Category)
   
    current = session.query(IP_History).filter(IP_History.IP == options.all1).one()
    print "\nHistoric Information\n"                  #Print all the information in on this IP in the historic data table
    print_ip(current.IP)
    print_location(current.Location)
    print_date(current.Date)
    print_score(current.Score)
    print_historic_category(current.Category)
  

else:
print "No options specified. Please type --help to see available options"

if len(sys.argv[1:]) == 0:
    parser.print_help()
