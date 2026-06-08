# The initials 
- You start the project the same way you would start a `Node` project : 
	- `npm init` , answer the questions
	- Then you install `express dependency`
		- `npm install express`

- Now we can start working with express
	- `import express from 'express'` Remember add `"type":module,` in `package.json`
	- Then we do create the server :
```js
import express from 'express'
const PORT = 9999
const app = express() // this holds an instance of the express application

app.listen(PORT, () => console.log(`server connected on port ${PORT}`))
```

# Sending Response
- If you log the `app` instance variable you would see a lot of methods that you can use : 
```js
delete
get
post
copy
merge
link
connect
// etc.
```
- And so if we're expecting a get request we will do : `app.get()`
	- A post request : `app.post()` and so on

- Right now, we're expecting a get request so let's work with that:
	- `.get()` takes 2 params : 
		1. Domain root path : `/`, in the real world it will be a more complicated path 
		2. A callback function which takes 2 params : `req` and `res`
```js
app.get('/', (req, res) => {
	// serving the data here
})
```

> NOTE : Data is mostly if not all the times is in JSON format, but when serving it we have to transform it to a text-based format because of HTTP
> Since we're working with express, we don't have to do that work ourselves : Express.js will take care of that for us hhhhhhh

- Then we can send the response using the `res` param with the `.json()` method :
	- `res.json( <data> )` // Data will be a JSON string here

## The request Object
- It contains a lot of info about the request made by the client :
	- `req.body` : Data from the request body
	- `req.params`
	- `req.method`
	- `req.ip` : get the client's IP
	- `req.query` : The query params

### Query params
- Using the `req.query` it's very easy to get the query params in a formatted way (Object)

> If you remember this was a pain to do in Pure NODE.js

- To filter the data you give to the client based on the `query` params, you can do something like this 
```js

// This is a simple beautiful code, easy to read and maintain

  let filteredData = startups
  
  // Destructure the Query Object
  const { industry, country, continent, is_seeking_funding, has_mvp } = req.query

 // Check if client included the option in the filter
  if (industry) {
  
  // Return the Data filtered
    filteredData = filteredData.filter( startup =>
startup.industry.toLowerCase() === industry.toLowerCase()
)}

// Do the same for every other Filtering Option
```

> Just make sure when you're filtering Booleans you make sure both comparison parties are Boolean, because What you have in data might be Boolean, but the query's is a String
> So you can use `JSON.parse( <query Boolean> )` 

## Path params
- Again Express comes in Clutch, and facilitates for us to get the path params : making sure it comes in an object using `req.params`
- To allow the user to choose what path he wants and get that param dynamically we do this :
	- In the first param of `app.get()` we place a `:` in front of the path param (aka piece of path) that the user can change 
```js
app.get('/api/crypto-name/:currency', (req, res) => {
	console.log(req.params)
})

// currency is just a name we chose
```
- Now if the user navigates to `/api/crypto-name/btc` and we console log it we get : `{ currency: 'btc'}` 

- EXAMPLE :
```js
app.get('/api/:field/:term', (req, res) => {

  const {field, term} = req.params
  let filteredData = startups

  const filteredData = startups.filter(
    startup => startup[field].toLowerCase() === term.toLowerCase()
  )
  
  res.json(filteredData)
})
```

> NOTE : the example above has some flaws : it doesn't handle the case where the user types in a field we're not expecting, you can counter that by using an `allowedFields` array, changing the status code using `res.status(400)` and sending the user an object which can be something like this :
> `{message: "Search field not allowed. Please use only 'country', 'continent', 'industry'" }`
> You can use `.includes` to see if the field is in the array

> ***Let's do some labeling*** : 
>- So this section is just to get us familiar with couple of keywords :
	- Route : The Path (e.g. `/api/products`)
	- Controller : The function/logic that will be executed when that Route is called 

# .Router()
- You added it to handle a specific set of Routes
- You would wanna add it always
- Add it after you add your `express` instance
```js
// This one will handle every route that starts with /api
// Thus the naming `apiRouter`
const apiRouter = express.Router()
```
- You then would put for each Route a controller function, usually this is done by modulization : a `controllers` folder and `routes` folder

- In your `server.js` file things will look like this :
```js
import express from 'express'

const app = express()
const apiRouter = express.Router() // In the Routes folder, must be exported
// and imported in the server.js

const productsController = (req, res) => { // In the controllers folder
    res.json({data: 'products'})
}

const servicesController = (req, res) => { // In the controllers folder
    res.json({data: 'service'})
}

// You don't do `/api/products` here, because we add `/api` at the bottom
apiRouter.get('/products', productsController) // In the Routes folder
apiRouter.get('/services', servicesController) // In the Routes folder

// Here
app.use('/api', apiRouter)  
app.listen(8000, () => console.log('listening 8000'))
```

> Follow those comments ^^ to know where to put things in a real project

- Now let's say the user got the whole endpoint wrong, here is a way to serve a `404`, so inside the `server.js`
```js
app.use((req, res) => {
    res.status(404).json({message: 'Endpoint not found'})
})
```

> If you need to have a route for just `/api` you can do this :
> `apiRouter.get('/', <function>)` 

> When the use gets the whole root wrong, so they didn't use `/api` we do this 
```js
app.use('/api', apiRouter) // if correct

app.use((req, res) => { // if incorrect
  res.status(404).json({ message: "Endpoint not found. Please check the API documentation." })
})
```

# CORS
- If you wanna upload this api now, the users will get blocked because of something called : Same Origin Policy, which is checked by the browser, where the Protocol, domain and Port must be the same as the HOST (aka YOU)
- CORS helps us with that, and in Express we can do it very easily
	- `npm install cors`
	- `import cors from 'cors'` inside `server.js`
	- `app.use(cors())` MAKE sure you put it before your other `app.use` 

> JUST like that you can now build a RESTApi

# Middleware
- It comes after the client sends the request and before the server sends the response
- Middleware are functions that can modify the response or request objects or end the response early if necessary, like :
	- Enabling CORS
	- Parsing requests
	- Logging requests/errors
	- ...
- There are 3 types :
	- Custom : Built by us
	- Built-in : Provided by Express
	- 3rd Party : Outside packages

> Everything we do in Express is based on the Middleware pattern so do read about it [here](https://expressjs.com/en/guide/using-middleware/) 

- To add Middleware, we mostly use `app.use`, here it takes 3 params :
	- `req` , `res` and `next` which is the function that will be called once the middleware function we're creating has completed
```js
app.use((req, res, next) => {
	console.log('something')
	next() // This will call the next function
})

// This one
app.use((req, res, next) => {
	console.log('something else')
	next() // And so on
})
```
- The example above shows `Custom` middleware, where we manually call `next()`, the other cases it will be called under the hood

# Serving Static pages
- We can achieve that using :
	- `app.use(express.static("<front-end-folder>"))`

# Creating a DB table using SQLite
- Install these :
	- `npm install sqlite3` : will be The DB driver > SQL commands, opens connection to the DB file
	- `npm install sqlite` : Will be a wrapper > Provides async/await support (basically making SQLite3 more modern)
- Create a file `createTable.js` 
	- Import the following :
```js
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'node:path'
```

- Working with DBs is an ASYNC process, so first let's make a function that creates our Table: create an instance of our DB, and execute SQL in our DB
```js
async function createTable() {
	const db = await open({ // open a connection, create an instance
		filename: path.join('database.db'), // will create our .db file
		driver: sqlite3.Database
	})
	
	// Executing SQL code
	await db.exec(` 
		CREATE TABLE IF NOT EXISTS voidpacket (
			<You would put columns you want to include>
			
			id INTEGER PRIMARY KEY,
			title TEXT NOT NULL,
			artist TEXT NOT NULL,
			price REAL NOT NULL
		)
	`)
	
	await db.close() // close the connection
}

createTable() // calling it
```
- Now you can run this file in your terminal using :
	- `node createTable.js`
- Then to log your DB table you can use this helper function, put it in a different file `logTable.js`, `node logTable.js` 
```js
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'node:path'

export async function viewAllProducts() {
  const db = await open({
    filename: path.join('database.db'),
    driver: sqlite3.Database
  })
  
  try {
    const abductions = await db.all('SELECT * FROM voidpacket')
    console.table(abductions) // This logs it in a table format
  } catch (err) {
    console.error('Error fetching products:', err.message)
  } finally {
    await db.close()
  }
}

viewAllProducts()
```

> Sometimes if not all the time you will need to change this code above a bit so that the logged table is logged beautifully 

## USEFUL SQLite3 methods
### db.exec()
- Used when you want to run multiple statements at once, like Schema setup
- DOEASN'T RETURN A THING
### db.run()
- Used to run a single statement, like updating, inserting and deleting 
- DOEASN'T RETURN A THING
### db.get()
- Used when you want One Row back (or the first Row), like when you look up a row by id
### db.all()
- Used when you want all matching rows from a table as an array, like selecting all in stock products

## Seeding a Table 
- Inserting into the Table, a lot of times we have to deal with variables right, and in JS we use `${}`, but in SQLite it's like C/C++ but we use `?` followed by an array of those variables
```js
await db.run(`INSERT INTO abductions (location, details) VALUES (?, ?)`, [location, details])
```

> NOTE : USING placeholders `?` prevent against SQL injection attacks 

- And the full code will look like this :
```js
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'node:path'
import { abductionsData } from './abductionsData.js'
  
async function seedTable() {
  const db = await open({
    filename: path.join('database.db'),
    driver: sqlite3.Database
  })

  try {
    await db.exec('BEGIN TRANSACTION') // To make it faster

    for (const {location, details} of abductionsData) {
      await db.run(
        `INSERT INTO abductions (location, details)
        VALUES (?, ?)`,
        [location, details]
      )
    }
    
    await db.exec('COMMIT') // and this too
    console.log('All records inserted')
    
  } catch (err) {
    await db.exec('ROLLBACK') // For error handling
    console.log('Error inserting data', err.message)
    
  } finally {
    await db.close()
    console.log('connection closed')
  }
}
  
seedTable()
```

## Get data
- You can use `await db.all()`
```js
const abductions = await db.all(`SELECT * FROM abductions`)
```
- This code is vulnerable, it will be executed in the front-end so a user can manipulate it etc., it's better to use placeholders : 
```js
const query = 'SELECT * FROM abductions WHERE location = ?'
const params = ['Roswell'] // this is the user's input 

const abductions = await db.all(query, params)
```


> NOTE : in the real world instead of every time having to create a connection with our DB, we just make a file that does that for us and we use when we want: create a folder `db` inside it a file called `db.js` and use this code bellow:

```js
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'node:path'

export async function getDBConnection() {

const dbPath = path.join('database.db')

 return open({
   filename: dbPath,
   driver: sqlite3.Database
 })

}
```

>  As for those `createTable.js` `seedTable.js` these are single use and that's it, we can delete them 


# Authentication
- So this is the most fun topic for me, so am writing this just to remind myself on how excited i was when i started learning it

- Now let's start for real 
## Creating the users table
- Obviously you need a table to register your users info, you can do this in your `createTable.js` 
```js
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import path from 'node:path'

async function createTable() {

      const db = await open({
            filename: path.join('database.db'),
            driver: sqlite3.database
      })

      await db.insert(`
            CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
      `)
  
      await db.close()
      console.log('table created')
}

createTable()
```

## Get users signed up and logged in
- There are 5 steps :
	1. Create a route for the `api/auth/register` endpoint
	2. Validate and sanitize user input 
	3. Add new user to the `users` table
	4. Think about password security in the DB
	5. Create a session for the user

### Creating the route 
- So you'll need a front end file that handles taking the data from the signing form and passing them to our server as a `POST REQUEST` where you'll pass those data in the body, the code can be like this :

```js
const signupForm = document.getElementById('signup-form')
const errorMessage = document.getElementById('error-message')

signupForm.addEventListener('submit', async (e) => {
  e.preventDefault() // Prevent form from reloading

  const name = document.getElementById('signup-name').value.trim()
  const email = document.getElementById('signup-email').value.trim()
  const username = document.getElementById('signup-username').value.trim()
  const password = document.getElementById('signup-password').value.trim()
  const submitBtn = signupForm.querySelector('button')

  errorMessage.textContent = '' // Clear old errors
  submitBtn.disabled = true

  try {
    const res = await fetch('api/auth/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ name, email, username, password })
    })

    const data = await res.json()

    if (res.ok) {
      window.location.href = '/'
    } else {
      errorMessage.textContent = data.error || 'Registration failed. Please try again.'
    }
  } catch (err) {
    console.error('Network error:', err)
    errorMessage.textContent = 'Unable to connect. Please try again.'
  } finally {
    submitBtn.disabled = false
  }
})
```


- Then you need to create a route in the routes folder and it's controller in the controllers folder like you would do, then we need to make some changes in the `server.js` file
	- Since Express.js doesn't parse incoming request bodies by default, you need to add body-parsing middleware _above_ your router declarations
	- We need the `req.body` cause well it contains the data

```js
// 1. Add this to parse JSON bodies (for applications/json) 
app.use(express.json()); 

// 2. Add this to parse form data (for application/x-www-form-urlencoded) 
app.use(express.urlencoded({ extended: true }));
```

and then you would need to add the `app.use` for that specific route
- `app.use('/api/auth', authRouter)`

### Validating and sanitizing user input
- So we can't do frontend validation cause it can be overridden by hackers, so we have to take care of that in the backend

- So here is what we need to do :
	1. Check if all fields exist
	2. Trim the whitespace from start and end
	3. Use regex in the username (not the name/fullname)
	4. Validating the email address (check if it's a valid email)
		- Using an npm package called : [The validator](https://www.npmjs.com/package/validator) using it's `isEmail(<email>)` method 

### Adding users to DB

> Pro tip : now we first need to check if the username and email are already used (avoiding duplicates) , and the best way to do that is : to query the DB : saying hey look for a user with this username OR this email and if the DB finds it, we now know that that username or email already exists and we can end the response and send a message to the frontend saying the registration has failed because this is a duplicate etc.

- It will look something like this :
```js
try {

    const db = await getDBConnection()
    const existing = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [email, username])

    if (existing) {
      return res.status(400).json({ error: 'Email or username already in use.' })
    }
    const result = await db.run('INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)', [name, email, username, password])

    res.status(201).json({ message: 'User registered'})
```

