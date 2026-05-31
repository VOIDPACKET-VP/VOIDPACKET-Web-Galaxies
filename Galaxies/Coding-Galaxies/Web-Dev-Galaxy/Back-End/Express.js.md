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