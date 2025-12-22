- Node.js is not a language, it's an environment where we can write JavaScript
# Project : REST API
## Package.json
- It's a `.json` file that exists at the heart of every node.js project.
- It acts as the projects blueprint :
	  1. Manages dependencies
	  2. Defining start script
	  3. Contains Metadata

- Creating this `json` file is the first thing we do, we can use the command : `nmp init` , then answer some questions ( if you hit enter without entering something, it will use the default option )
- When it's created, now instead of entering this : `node <file name>` in the terminal to run our code, we would use `npm start` 

## HTTP Module
- To be able to import modules in `node` we need to add in the `package.json` this : `"type": "module"` .
- Then we can import what we need using `import <what you want>` :
	1. For our case (http) > `import http from 'http'` 
- It is considered a best practice to include `'node:http'` to tell the app that we're looking for a **NODE Module** :
	  - `import http from 'node:http'` 

- We mainly we'll be using the `.createServer()` method from the HTTP Module, and it goes like this :
	1. it takes a callBack function, which takes 2 params : `request` and `response`
	2. The `response`  param exposes various methods to us, one of them is the `.end()` : which sends data over HTTP and then ends the response, it takes 3 params :
		   1. The data
		   2. An encoding type : the default is `utf8` 
		   3. A callback function
		Another method is the `.write()`, the difference between the `.write and .end` is that the `.end` also ends the request.
	- So to create a server we would do something like this :
		`import http from 'node:http'`
		`const PORT = 8000`   ***// We need to set up a PORT to listen to***
		`const server = http.createServer((req, res) => {`
		  `res.end('Hello from the server!')`
		`})`
		`server.listen(PORT, () => console.log(``server running on port: ${PORT}``))`  ***// and here is where we listen***


## Content-Type
- When sending data, specifying content type is very important.
### Types :
1. application/json
2. text/html
3. text/css
4. application/xml
5. etc.

- To set the content type in the backend, we use the `setHeader()`  method on the `response` object , and we pass into it 2 strings : `"Content-Type"` and `"application/json"` 
	- It will look something like this : `response.setHeader("Content-Type", "application/json")`

- When sending data, we need to specify the status Code as well, we do that using the `statusCode` property on the `response` object : > `response.statusCode = 200`

## Query parameters
- It's what we add after the `url` and we initialize it with `?` then between each *key-value pair* we separate them with `&` : `/api?name=voidpacket&country=morocco` 
- To construct them :
	1. we make a new URL constructor (it takes 2 params : relative URL and base URL) which returns a URL object > `const urlObj = new URL(req.url, 'http://${req.headers.host}')` 

	2. the `urlObj` now returns an object that has a key `searchParams` where it's value is : `{ 'name' => 'voidpacket', 'country' => 'morocco' }` , now this is not an object, so we have to make it an object, we do that using the `Object` class with the `fromEntries()` method : `const queryObj = Object.fromEntries(urlObj.searchParams)` 
- We can use `urlObj.pathname` instead of `req.url` when we want to get the ***path stripped from the query params***
## CORS
- So by default browser use : **Same-origin policy** > requests can only be made to the same `protocol` ,`domain` and `port` as the one serving the web page. (BTW, this is happening by default)
- But sometimes, things can get a bit complex, and so we need to override it (*Same-origin policy*), Therefor we use what's know as **Cross-origin resource sharing (CORS)** 
	1. CORS is enabled to allow KNOWN FRONT-ENDS :
		- So what we do is : we host the front-end with a different port than the back-end
	2. CORS is enabled to allow ALL ACCESS (e.g. for APIs), to do that we need to add `two headers` when sending `data` :
		1. `response.setHeaders("Access-Control-Allow-Origin", "*") ` // allows access from any origin
		2. `response.setHeader("Access-Control-Allow-Methods", "GET")`  // allows only the `GET` method

# Project : ROUTED SITE 
## .writeHead() Method
- The `.writeHead()` method is another method of the `response` object and it's used to write the status code, headers etc. in just one line of code.
	- `response.writeHead(200, {'Content-Type':'application/json'})` 
- So although it sounds like it's better to use `.writeHead()` method instead of `.setHeader()` it actually comes with some shortcomings :
	-  `.writeHead()` sends any headers immediately, while `.setHeader()` doesn't which allows you to set, modify it at any point before sending the response.
	- We can't set headers with `.setHeader()` ***AFTER*** using `.writeHead()` 
	- Header set with `.setHeader()` can be overruled by a header set with `.writeHead()` 
	- And to top if off : ***YOU WON'T GET ANY ERRORS, YOU WILL GET UNEXPECTED BEHAVIOR*** 

## Reading and Serving Data

- We will have to be *OS agnostic* : we need a solution that doesn't care about what operating system we're using.
- In our case we will need to generalize the file paths so that our users can get there hands on the resources without any OS problems.
### Get current module directory
- So we will need to use `import.meta` : an object of modular JS environment which provides metadata on the current module
	- We'll try it with `server.js` since it's our module, if we log out `import.meta` this is what we get :
		`[Object: null prototype] {`
		`dirname : '/home/projects/bkabkabkab',`
		`filename: '/home/projects/bkabkabkab/server.js',`
		`resolve : [Function: resolve],`
		`url : 'file:///home/projects/bkabkabkab/server.js'`
		`}`
	- The `dirname` object is the directory of our module, we can access it using : `import.meta.dirname` 
- In normal JS, we can access that directory just with : `__dirname` (it's by default a global variable)

### Path to resource from that directory