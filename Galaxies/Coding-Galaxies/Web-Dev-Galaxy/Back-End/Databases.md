 - They allow us to store and manage data
 - The storage is ***persistent***, meaning it is preserved in between user visits and across the app
 - DBs offer a structured way to store data often within **TABLES** 
 - Every DB will have a ***SCHEMA*** which defines the shape of the data within it
# *SQL vs NoSQL*

- SQL stands for : Structured Query Language
## **SQL**
- SQL DBs are ***relational*** which means that data stored is interconnected
- Data follows a strict structure which is organized into TABLES
- It's so popular : Used with MySQL, PostgreSQL, Microsoft SQL, Oracle SQL ...
- Easy to learn
- It's built around the **Mathematical SET THEORY** : study of groups of information, they are linked together through relations
- It uses SQL as a language
## **NoSQL**
- NoSQL DBs are ***non-relational*** : data is defined with a looser structure and less strict relationships 
- They can be more flexible and allow for less rigid data structure 
- The DBs are less structured > More flexible
- There are different types of NoSQL DBs which can be used for different types of app :
	1. *Document Store DB* (e.g. MongoDB) : stores data in documents (e.g. JSON), each document represent a record > Content management apps use this .
	2. *Key-Value Stores DB* (e.g. Redis) : stores data in a key-value pair > APIs use this .
	3. *Column-Family Stores* (e.g. Cassandra) : Designed for handling large volumes of data across distributed systems, data is stored in **columns** and grouped into **column families** > Used for time-series data, logging, event tracking .
	4. etc.
- It uses multiple languages : MongoDB, CQL, Cypher ... 
## **Schema** 
- It defines DB tables and relationships
- It's a representation of the columns and types in the table

# *Working with DBs*
## **Application structure** 
- It has 3 parts :
	1. **Frontend** which the user interacts with > A web browser
	2. **Backend** which runs a server and has an API that interacts with the frontend, the API will be sending info back and forth to the DB
	3. **DB** > we use our RDBMS (relational DB management system) so that the API can interact with our DB

## **Interacting with the DB**
- There are various libraries that allow us to interact with DBs such as : SQLite, SQLAlchemy ...
- Another approach to interact with DBs is using **OBJECT RELATIONAL MAPPING** (ORM), it allows us to use an ***Object oriented approach*** rather than writing SQL queries : this means we can write queries in languages like *JavaScript*, *Python* ... , then the ORM will translate the data between our Application code and the Database
- Example of an ORM : ***Prisma***

## **Managed VS Self-Hosted**
- DBs can either be managed on cloud storage, or hosted in our own infrastructure .
### *DB Administration* 
- It's the practice of managing a production DB with regards to creating, dropping tables, managing access and controlling data
### *Managed DB*
- It's a cloud based solution provided by third party provider
- Avoids managing a DB and maintaining infrastructure 
### Self-Hosted
- DB is ran in house
- We don't rely on third parties
- We will have to deal with everything


# ***Intro To SQL***
