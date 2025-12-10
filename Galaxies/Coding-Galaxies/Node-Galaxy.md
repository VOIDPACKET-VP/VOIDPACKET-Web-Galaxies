- Node.js is not a language, it's an environment where we can write JavaScript

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
	2. The `response`  param exposes various methods to us, one of them is the `.end()` : which sends data over HTTP and then ends the response
	- So to create a server we would do something like this :
		`import http from 'node:http'`
		`const PORT = 8000`   ***// We need to set up a PORT to listen to***
		`const server = http.createServer((req, res) => {`
		  `res.end('Hello from the server!')`
		`})`
		`server.listen(PORT, () => console.log(``server running on port: ${PORT}``))`  ***// and here is where we listen***

