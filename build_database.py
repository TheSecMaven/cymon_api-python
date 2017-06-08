#Miclain Keffeler
#6/6/2017
#This file creates 2 tables within the SQL Database that is named "IP_Report.db". One table is used to hold current information while the other is used to hold historic information
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()
class IP_Current(Base):    #Table to hold most up to date score and Category on a given IP Address 
    __tablename__ = 'current'               
    IP = Column(String(250), primary_key=True)       #Here we define each column in the table, Notice that each column is also a normal Python instance attribute.
    Location = Column(String(250),nullable=True)
    Date = Column(String(250),nullable=True) 
    Score = Column(String(250), nullable=False)
    #Current Category is under "Cats" in JSON
    Category = Column(String(250),nullable=True)
    registrar_name = Column(String(250),nullable=True)
    registrar_organization = Column(String(250),nullable=True)

class IP_History(Base):          #Table to hold historic scores, categories, and dates of an IP
    __tablename__ = 'address'
    IP = Column(String(250),primary_key=True)
    Location = Column(String(250),nullable=True)
    Date = Column(String(250),nullable=True)
    Score = Column(String(250),nullable=True)
    Category = Column(String(250), nullable=True)
    registrar_name = Column(String(250),nullable=True)
    registrar_organization = Column(String(250),nullable=True)

engine = create_engine('sqlite:///IP_Report.db')      #Create an engine that stores data in the local directory, IP_Report.db file.
 
Base.metadata.create_all(engine)    #Create all tables in the engine. Equivalent to "Create table" statement in raw SQL.
