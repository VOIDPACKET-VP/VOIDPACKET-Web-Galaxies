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
## Relationships
- Tables relate to one another through different properties. Usually, we'll link based on *primary keys* : The unique id for each row

- There are different Types of relationship: 
	1. One to one : one row relating to one row in another table
	2. One to many
	3. Many to many

> Foreign key : unique id which references another table

- Each column will have a type of data that we can insert, and constraints : data to not insert

## Creating Tables
- Syntax : 
```sql
CREATE TABLE IF NOT EXISTS dealerships ( /* choose any name you want */
	id SERIAL PRIMARY KEY,  /* SERIAL : we want it to increment */
/*  name | Type | Constraints  */
	city TEXT NOT NULL, 
	state CHAR(2) NOT NULL, 
	established DATE NOT NULL
);
```

- To have the ONE TO MANY relation :
```sql
CREATE TABLE IF NOT EXISTS staff (
  id SERIAL PRIMARY KEY,
  /* Here below you can see we are referencing the dealership's id */
  dealership_id INTEGER NOT NULL REFERENCES dealerships(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  role TEXT NOT NULL
);
```
 > Basically this is the Foreign key : dealership_id INTEGER NOT NULL REFERENCES dealerships(id) ON DELETE CASCADE,
 > The "ON DELETE CASCADE" without it, Postgres will prevent you from deleting a dealership if it still has staff members assigned to it
 
 > To make it one to one, we add "UNIQUE" constraint to the foreign key column
## Populating tables (adding data)
- You would simply use `INSERT INTO`

## Alter table
> So first let's understand what the word alter means hhhhh : it means to change or modify something

- So now that we have our tables and we populated them, we don't have a way to know which dealership the car is at
- SYNTAX plus steps : 
```sql
 -- 1. Add the column (initially nullable)
/*the table to alter*/ 
ALTER TABLE cars  
/*the column of the table we wanna alter with*/ 
ADD COLUMN dealership_id INTEGER; 

-- 2. Insert data to backfill the dealership_id column
UPDATE cars SET
  dealership_id = 1
WHERE
  dealership_id IS NULL;

-- 3. Add the NOT NULL constraint
ALTER TABLE cars
ALTER COLUMN dealership_id SET NOT NULL;
  
-- 4. Add the foreign key constraint
ALTER TABLE cars
ADD CONSTRAINT dealership_fk FOREIGN KEY (dealership_id)
REFERENCES dealerships(id);

-- 5. Altering the cars table
ALTER TABLE cars
ALTER COLUMN brand SET NOT NULL,
ALTER COLUMN model SET NOT NULL,
ALTER COLUMN year SET NOT NULL,
ALTER COLUMN price SET NOT NULL,
ALTER COLUMN color SET NOT NULL,
ALTER COLUMN condition SET NOT NULL,
ALTER COLUMN sold SET NOT NULL;
```

- To understand this shit, here a more detailed explanation :
1. Preparing the Link (**Steps 1-3**)
	- **Step 1**: You create the new column `dealership_id`. It has to be "nullable" at first so the database can create it for your existing car records.
	- **Step 2**: You "backfill" the data. You are telling the database, "For every car already in this table, assume it belongs to dealership #1." This ensures there are no empty (NULL) spots left.
	- **Step 3**: Now that every row has a value, you can safely flip the switch to `SET NOT NULL`. This prevents anyone from adding a car without a dealership ID in the future.

4. Enforcing the Relationship (**Step 4**)
	- You establish a **Foreign Key**. This creates a formal "parent-child" relationship. The database will now double-check that any ID you put in the `cars` table actually exists in the `dealerships` table. You can't assign a car to a dealership that doesn't exist.

5. Cleaning Up the Rest (**The Final Block**)
	- You are applying the same `NOT NULL` logic to your core data columns (`brand`, `model`, etc.).
	- **The Goal:** You are transitioning the table from a "loose" state (where data could be missing) to a "strict" state. Moving forward, every car record **must** have a brand, price, year, and condition to be saved.

## Joining tables
- We can retrieve data from multiple tables, we can join tables in columns they have in common
- There are 4 types of JOIN :
	- INNER JOIN: returns matching values in both tables
	- RIGHT JOIN: returns all records from the right table plus matching values in the left table  
	- LEFT JOIN: opposite of RIGHT JOIN
	- FULL JOIN: returns everything from both tables
- JOIN clauses have 2 sides :
	- *LEFT* : table we select from
	- *RIGHT* : table we join with

### LEFT and RIGHT JOIN
- If we understand the links between our tables, we'll have a better time JOINING them
![[Screenshot 2026-05-09 201927.png]]

- SYNTAX : `LEFT JOIN <table> ON`
```sql
SELECT brand, model, price, sold, sold_price
  FROM sold_cars SC
  LEFT JOIN cars C ON SC.cars_id = C.id;
  
  /*We used an alias for sold_cars and cars : SC and C
So instead of typing sold_cars you type SC
  */
```
![[Screenshot 2026-05-09 202651.png]]

> NOTE : the left hand table comes always after the FROM, and the right one after the JOIN 

### FULL, INNER JOIN and DROP
#### DROP
- Allows us to remove tables, columns and constraints from the database
- Since we want to remove a constraints (a change) we will use `ALTER` :
```sql
ALTER TABLE staff
ALTER COLUMN dealership_id DROP NOT NULL;
```

#### FULL and INNER
- It's pretty similar to LEFT and RIGHT
