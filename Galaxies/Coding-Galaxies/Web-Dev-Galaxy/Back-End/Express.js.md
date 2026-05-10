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
- Rewatch the *Aside: Sending a Response* section : i didn't take notes 