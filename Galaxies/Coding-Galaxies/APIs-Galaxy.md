# API

- Stands for :  Application Programming Interface
# Promises

- A promise is an object that represents the state of completion of an ASYNC operation and it's resulting value.
- the fetch request returns a promise.
- Promises have 3 states :
	1. Pending
	2. Fulfilled
	3. Rejected
- The `.then`  runs that anonymous function when the state of the promise is `Fulfilled` .
- The `.then` returns a `Promise` , that promise is what get's chained to the next `.then` as a parameter to it's callback function, this is what's known as `Promise chaining` .
- A `fulfilled promise` only means that the fetch method will give us ***a response***, not necessarily ***data too***. 

	e.g. : Job interview > 
		- Once the interview is done they usually say we will get back to you within let's say a week.
		- Here they only promise you a response not necessarily that you got the JOB.

- If a promise is `rejected` ( an error occurred inside one of the .then methods ) an `error is thrown`.
- We use the `.catch` method for the *rejected case*, it goes after the the `.then` methods.
- It's syntax is similar to the `.then` : `.catch(err => {function-goes-here})`
- Devs will usually add a way to report the error to some kind of service so that they can fix it etc.
- Sometimes we can get a `404` but we don't get an error since `fetch` take it as a response, to overcome that we can use the `throw Error()` method with `!response.ok` as a condition in the `if statement` , which will throw an error and will skip to the `.catch`
# async and await 

- There whole purpose is to make asynchronous code appear synchronous .
- `async` goes before the function which enables us to use `await` , which goes anywhere before a method/function that returns a PROMISE.

	`async` function handleClick() {
	    const response = `await` fetch("<URL>")
	    const data = `await` res.json()
	    remainingText.textContent = 'Remaining cards: ${data.remaining}'
	    deckId = data.deck_id
	    console.log(deckId)
	}
- Since 2020 we don't need the `async` we can just use directly the `await` keyword, but in the `HTML` we have to add `type="module"` to our `script` tags  

# try ... catch....finally 

- We use it when we want to do something (using the `try{}` ) and if something goes wrong we do something else (using the `catch{}` ).
- (OPTIONAL) We can also add the `finally{}` block : it runs whether everything went well or not .
	try{
	
	} catch (err){
	
	} finally {
	
	}

# CallBack Hell
So instead of having a lot of functions where each one has a callback function, we can use Promises to ease that process up :
	Example :
	function uploadFile() {
		return new Promise((resolve, reject) => {
			console.log('Step 1: Uploading file...')
			 setTimeout(() => {
			          resolve() // Call the next step after 1 second
			       }, 1000)
			   })
	}
	function processFile() {
	    return new Promise((resolve, reject) => {
	        console.log('Step 2: Processing file...')
	        setTimeout(() => {
	            resolve() // Call the next step after 1 second
	        }, 1000)
	    })
	}
	function notifyUser() {
	    return new Promise((resolve, reject) => {
	        console.log('Step 3: Notifying user...')
	        setTimeout(() => {
	            resolve() // Call the next step after 1 second
	        }, 1000)
	    })
	} 

	try {
	    await uploadFile()
	    await processFile()
	    await notifyUser()
	    console.log('All steps completed!')
	} catch(err) {
	    console.log(err)
	}

# Promise.all

It's used when we want to execute multiple promises concurrently, so the result is either they all resolve or the catch block gets triggered.
	Example :
		function createPromise() {
		    return new Promise((resolve, reject) => {
		        const success = Math.random() > 0.5
		        if (success) {
		            resolve("Operation successful!")
		        } else {
		            reject("Operation failed.")
		        }
		    })
		}
		
		try {
		    const promise1 = createPromise()
		    const promise2 = createPromise()
		    const promise3 = createPromise()
		    const result = await Promise.all([promise1, promise2, promise3])
		    console.log(result)
		} catch(err) {
		    console.log(err)
		}
- Also the OUTPUT of the Promise.all is an ARRAY, so remember that.