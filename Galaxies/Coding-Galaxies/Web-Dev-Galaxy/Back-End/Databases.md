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
- All goes in a `.sql` file usually named `query.sql`
## Commands
### SELECT
- used to select data 
	- `SELECT * FROM <table_name>;` 
		- The `*` signifies `all` 
- You can also retrieve only desired columns
	- `SELECT <column>, <column> FROM <table_name>;`
### WHERE clause
- Used to filter results
- NOTE :  we can write in multiple lines, indentation is used to make things clean, just remember the `;` at the end of the query
- SYNTAX : `SELECT <something> FROM <table> WHERE <something> = '<condition>';`
```sql
// EXAMPLE
SELECT brand, model, condition, price FROM cars
	WHERE condition = 0;
```
- You can also do `> < >= <= !=`  
### NOT and LIKE
- Used to get a match, this is achieved by matching by multiple characters or a single char
	- Multiple : `%<match>%`
	- Single : `_`
```sql
// EXEMPLE WITH %
SELECT brand, model, color, year FROM cars
  WHERE color LIKE '%green%';
  
// EXAMPLE WITH _
SELECT brand, model, color, year FROM cars
  WHERE model LIKE 'DB_';
```
- We achieve the opposite by adding `NOT`
	- `WHERE color NOT LIKE '%green%';` 
### AND
```sql
SELECT brand, model, color, year FROM cars
  WHERE color NOT LIKE '%green%'
  AND model LIKE 'DB_'
  AND year > 1964;
```
### BETWEEN
- Used to set a range
```sql
SELECT brand, model, year, price FROM cars
  WHERE year BETWEEN 1980 AND 1989;
```
### OR
```sql
SELECT brand, model, condition, price FROM cars
  WHERE price < 250000
  OR brand = 'Porsche';
```

- THINGS TO NOTE :
```sql
// This 
SELECT brand, model, condition, price FROM cars
  WHERE price < 250000
  OR brand = 'Porsche'
  AND condition > 3;
// is as if we said 
SELECT brand, model, condition, price FROM cars
  WHERE price < 250000
  OR ( brand = 'Porsche'
  AND condition > 3 ); 
```
- So be careful with brackets
- Also when you wanna check something's value if it's `FALSE or TRUE` (Boolean) it's better to use `IS` instead of `equal` 
```sql
SELECT brand, model, color, year, price, sold FROM cars
  WHERE (color LIKE '%red%'
  OR year BETWEEN 1960 AND 1969)
  AND sold IS FALSE;
```

### IN 
- To look for multiple values within a column
- SYNTAX : `IN ('', '', '');`
```sql
SELECT brand, model, price, sold FROM cars
  WHERE brand IN ('Ford', 'Chevrolet', 'Ferrari')
  AND sold IS FALSE;
```

### ORDER BY
- Allows us to sort our results using different columns
	- The default sorting for strings is from A-Z, and it's ascending for Numbers : `ORDER BY <column>;`
	- We can reverse the sorting by adding `DESC` : `ORDER BY <column> DESC;`
- We can have multiple `columns`, the sorting starts with the first column then sorts using the second column and so on
	- `ORDER BY brand DESC, year;` 
```sql
/*
  Select the brand, model, condition and price from cars
    order the table by condition in descending order
    and by price in ascending order
*/

SELECT brand, model, condition, price FROM cars
  ORDER BY condition DESC, price;
```
- You can add the `WHERE clause` before the `ORDER BY`
```sql
SELECT brand, model, condition, price FROM cars
  WHERE sold IS FALSE
  AND condition != 5
  ORDER BY condition DESC, price;
```

### LIMIT
- Allows us to select a number of records 
```sql
SELECT brand, model, color, price FROM cars
  WHERE color LIKE '%red%'
  AND sold IS FALSE
  ORDER BY price
  LIMIT 5;
```

### Aggregations : 
#### COUNT and SUM
- Allow us to turn values of a column to a single value
- SYNTAX : `COUNT(<COLUMN>)` and `SUM(<COLUMN>)`
```sql
SELECT COUNT(*) AS total_sold FROM cars
  WHERE sold IS TRUE;
  /*
 Result
|index|total_sold |
|  0  | 19        |
  */
```
- NOTE : `AS total_sold` is optional, it's like giving it a name
```sql
SELECT SUM(price) AS total_earnings FROM cars
  WHERE sold IS TRUE;
```

#### MAX, MIN and AVG
- You can understand what they do from their name
- SYNTAX : same as `COUNT`

> We can FLOOR or CEIL our results if they were numerical:
> FLOOR(MAX(price))

#### GROUP BY
- Well we group by something hhhhhhh
```sql
SELECT brand, COUNT(brand) AS brand_count FROM cars
  GROUP BY brand;
```

```sql
/*
  Select:
    * the brand
    * a count of the brand
    * and an average of the price for each brand
    * round the average down to the nearest number
    * alias the average as 'AVG' in your output
  From cars where
    the car has not been sold
  Group the table by brand.
*/

SELECT brand, COUNT(brand), FLOOR(AVG(price)) as AVG FROM cars
  WHERE sold IS FALSE
  GROUP BY brand;
```

#### HAVING
- Allows us to add conditions for our aggregations
```sql
/*
  Select:
    * the brand
    * a count of the brand
    * and an average of the price for each brand
    * round the average down to the nearest number
    * alias the average as 'AVG' in your output
  From cars where
    the car has not been sold
  Group the table by brand.
  Show results where the count is > 1
*/

SELECT brand, count(brand), FLOOR(AVG(price)) AS AVG
  FROM cars
  WHERE sold IS FALSE
  GROUP BY brand
  HAVING count(brand) > 1;
```

### Challenge
```sql
/*
  Select:
    * year
    * a count of cars from that year, aliased as car_count
    * the maximum price
    * the minimum price
  from the table cars
    where the car has been sold
  group by year
    only show years where more than one car has been sold from that year
  order the result by car_count
*/

SELECT year, COUNT(year) as car_count, MAX(price), MIN(price) FROM cars
  WHERE sold IS TRUE
  GROUP BY year
  HAVING COUNT(year) > 1
  ORDER BY car_count;
```

> GROUP BY and HAVING have to come before ORDER BY

## Manipulating Data
- These operations are known ad `DATA MANIPULATION LANGUAGE (DML)` or `CRUD Commands` : Create, Read, Update, Delete

> DML commands don't return data from the db

### INSERT INTO
- It's best to write into every column, this makes us avoid null values in our columns
- SYNTAX : `INSERT INTO <table> (<columns to write to>) VALUES (<values for each volumn respectively>), (<another set of values if any>), (<and so on>);` 

### UPDATE
- It's best to be specific as possible, so adding conditions is a good idea
- SYNTAX : `UPDATE <table> SET <column> = <value>, <column> = <value>`
```sql
UPDATE cars SET
  condition = 5,
  price = 465000
WHERE
  id = 14;
```

### DELETE
- SYNTAX : `DELETE FROM <table> WHERE <condition>`
```sql
DELETE FROM cars
	WHERE condition = 0;
```

# Creating and Joining Tables
