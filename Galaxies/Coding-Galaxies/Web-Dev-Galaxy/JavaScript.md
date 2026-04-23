# HTML elements
- if we only have one type of an html element in our HTML document, we can control it just by :
	  `document.<elementName>`
	  e.g. :  `document.body`
- We can update the `css` style of an element using `JS` using : `<element>.style` :
- ```
  // On click we change the display property 
  
	const revealBtn = document.getElementById('reveal-btn')
	const answer = document.getElementById('answer')
	revealBtn.addEventListener('click', function(){
	    answer.style.display = 'block'
	})
  ```

# How to turn Objects into Arrays
- Let's say we have the following object :
  ```
  const loginCredentials = {
    "rafidhoda": "BestPassword123",
    "shahrukhkhan": "InBigCitiesSmallThingsHappen",
    "jackblack": "ThisIsNotTheGreatestPasswordInTheWorld"
}
  ```
- We use
```
Object.keys(<the object>) // To get only the keys
Object.values(<the object>) // To get only the values
Object.entries(<the object>) // To get key value pairs in an array
```

# Something cool we can do is :
- So instead of making a mobile app, we can actually make our web app be a mobile app, they are called `Progressive Web App` :
	- It looks and feels like a Mobile app
```
This is what we need, a site.webmanifest file that contains :

{
    "name":"",
    "short_name":"",
    "icons":[
        {"src":"/android-chrome-192x192.png","sizes":"192x192","type":"image/png"},{"src":"/android-chrome-512x512.png","sizes":"512x512","type":"image/png"}
        ],
    "theme_color":"#ffffff",
    "background_color":"#ffffff",
    "display":"standalone"
}
```

# Advanced JS 
## Advanced Foundations
### Ternary Operator
- Alternative of `if/else` statements (sometimes)
- Syntax : `condition ? expression_if_true : expression_if_false`
```

const exerciseTimeMins = 20

// let message = ''
// if (exerciseTimeMins < 30) {
//     message = 'You need to try harder!'
// }
// else {
//     message = 'Doing good!'
// }

const message = exerciseTimeMins < 30 ? 'You need to try harder!' : 'Doing good!'

```

- For complex conditional logic : It's recommended to stick with `if/else` 
### Switch Statements
- Similar to `C` : it selects one of many code blocks to execute
- Syntax : 
```
switch(<thing_to_compare_to>) {
	case <thing_to_compare_with> :
		<code_to_execute_if_true>
		break // to break from the switch
		
	case <thing_to_compare_with> :
		<code_to_execute_if_true>
		break
		
	// and so on
	
	default: // This is the case that will be executed if none of the above is executed
		<code_to_execute_if_true>
}
```

### Object Destructuring
- Enables us to extract properties from objects into distinct variables
- Syntax : `const {variables} = <object to destructure>`
```
const favouriteFilm = {
    title: "Top Gun",
    year: "1986",
    genre: "action",
    star: "Tom Cruise",
    director: "Tony Scott"
}

// we do this
const {title, year, genre, star, director} = favouriteFilm

// instead of this :
const title = favouriteFilm.title
const year = favouriteFilm.year
const genre = favouriteFilm.genre
const star = favouriteFilm.star
const director = favouriteFilm.director
```

### setTimeout() 
- We can use `setTimeout()` which executes code after a specified amount of time : `setTimeout(<function>, <time in ms>)`
- When we have a function that need to take params this is the new syntax : `setTimeout(<function>, <time in ms>, <param>)` 
- We can stop a `setTimeout` using `clearTimeout` 
```
const questionTimer = setTimeout(logAnswer, 3000, 'Lima', 10)
clearTimeout(questionTimer)
```

### setInterval()
- It repeats executing code every duration, same syntax as `setTimeout`

### The Event Loop
1. The Fact: JavaScript is **Single-Threaded**. It has one "Call Stack." It can only do **one** thing at a time.
2. The Problem: If JS had to wait for a 5-second API call (like your **Strava API** check), the whole website would freeze.
3. The "Friends" (Web APIs): JS doesn't do the heavy waiting itself. It offloads tasks to the **Browser** (or Node.js runtime). These "friends" include:
	- `setTimeout` (The Timer)
	- `fetch` (The Network Request)    
	- `DOM Events` (The Click Listener)
4. The Process:
	1. **Call Stack:** JS sees a `fetch()`. It tells the Browser: _"Hey, go get this data, I'm busy."_
	2. **Web API:** The Browser handles the network request in the background (Multi-tasking!).
	3. **Callback Queue:** Once the data is back, the task waits in a "line" (the Queue).
	4. **The Event Loop:** This is the "Security Guard." It constantly checks: _"Is the Call Stack empty?"_ * If **Yes** -> It pushes the next task from the Queue into the Stack.
	    - If **No** -> It waits.

### Import and export
- To import something (function, array etc.) you have to add `export` before it, Then in the file where you wanna import it : `import { <thing to import> } from '<location>'`
- You can change the name of what you wanna import : `import { <thing_to_import> as <new_name> } from '<location>'`
- To export things all at once of a file use this : `export {<thing_to_export>, <thing_to_export>}`
- There is another way to export : the `default` export, in front of what you wanna export add : `export default`, and to import : same syntax but without `{}` 
	- It allows us to change the name directly of what we exported
	- You can have one `default export` per file

### Date() constructor
- A constructor gives us an Object
- To get a Date for example : `const dateSnapshot = new Date()` 
- There is a lot of ways to get the user's local time, but it always starts with using the in built function : `Date()`
- So it starts like this : 
	- `const now = new Date()`
- Then we can use it's other methods like :
	1. `now.getMinutes()`
	2. `now.getHours()`
	3. You can days, months etc.
- This will be in the 24hour format, to change that we can use the `Intl.DateTimeFormat()` method, so it goes like this :
	- `const formatter = new Intl.DateTimeFormat('en-US', {`  
		`hour: 'numeric',`  
		`minute: 'numeric',`  
		`hour12: true
	`});`
		`console.log(formatter.format(now))` // will log something like `1:23 PM` 
- You can also use this instead of the `IntL.DateTimeFormat()` :
	  `now.toLocaleTimeString("en-us", {timeStyle: "short"})`
- To update the time each `periode of time` we can use the `setInterval(fn, <time>)` function :
```
function getCurrentTime() {
	const date = new Date()
	document.getElementById("time").textContent = date.toLocaleTimeString("en-us", {timeStyle: "short"})
		}
	setInterval(getCurrentTime, 1000)
```

### Error() constructor
- Gives us the ability to create an Error function
```
function checkUsername(userName) {
	if (userName) {
		console.log(userName)
	} else {
		throw new Error('No username provided') //the throw keyword will stop every code that follow the Error()
		console.log('voidpacket') //this will not execute, so we can use just console.log(new Error()) instead
	}
}
```

### Common Constructors 
1. String()
2. Number()
3. Array()
4. Object()
5. Boolean()
- So we can do stuff like this : 
```
const person = new Object()
person.name = 'VOID'

// This is not a common way of creating them, so use the normal way :

const person = {}
person.name = 'VOID'
```
- But for `Objects` we will be using this way of creating them 

### Numeric Separators & BigInt
- Numeric separators helps us separate big numbers with `_` to make them easier to read : `9_007_199_254_740_991`
- So numbers bigger than `9_007_199_254_740_991` are considered not safe so we make them of type `BigInt` and we can do that in 2 ways :
	1. appending `n` at the end : `9_007_199_254_740_991_121n`
	2. or using : `BigInt(9_007_199_254_740_991_121)` 
- We can't mix BigInt with normal numbers.

### Hoisting
- It basically allows us to execute/access declared variables and functions before we reach them in code by moving them to the top during compilation

## Methods & Loops
### for...of
- It's a nicer way of iterating through arrays (are type of objects)
- Syntax :
	- `for (let <name_for_current_element> of <array>) {}` it's similar to python
- EXAMPLE :
```
const characters = [
    {
        title: 'Ninja',
        emoji: '🥷',
        powers: ['agility', 'stealth', 'aggression'],
    },
    {
        title: 'Sorcerer',
        emoji: '🧙',
        powers: ['magic', 'invisibility', 'necromancy'],
    },
    {
        title: 'Ogre',
        emoji: '👹',
        powers: ['power', 'stamina', 'shapeshifting'],
    },
    {
        title: 'Unicorn',
        emoji: '🦄',
        powers: [ 'flight', 'power', 'purity'],
    }
]

// To iterate over the powers arrays we can use for of :

for (let character of characters){
    for (let power of character.powers){
        console.log(power)
    }
}
```
### For...in
- Syntax : similar to `for...of`
- So what's the difference :

| for...of                                                                      | for...in                                                         |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Use it to iterate over the values of an iterable object : strings, arrays ... | Use it to iterate over all enumerable property keys of an object |
### .forEach()
- It's a method to iterate over arrays
- Syntax : `<array>.forEach(function(<name_for_current_element>){ <code> })`
- It's the same as `for...of` but this one is much neater
- If we take the same example in the `for...of`, we can do the same thing by nesting a `.forEach()`
```
characters.forEach(function(character){
    character.powers.forEach(function(power){
        console.log(power)
    })
})
```
- We can even know the index :
	- `characters.forEach(function(character, index){}` 

### .includes()
- Allows us to check if an array holds a given value
- Syntax : `<array>.includes(<what we wanna look for>)` : it returns Boolean value : `true or false`

### .map()
- It's again for iterating over arrays
- This method returns an ARRAY which we can store in a var or return it with a function (see example)
- Syntax : 
	- `const newArray = <array>.map(function( <name_for_current_element> ) { <code> } )` 
- EXAMPLE :
```
//Convert these Miles to KM!

// (Store in a var)
const distanceMilesArr = [140, 153, 161, 153, 128, 148]
const conversionFactorMilesToKm = 1.6

const distanceKmArr =distanceMilesArr.map(function(distanceMiles){
    return distanceMiles * conversionFactorMilesToKm
})

-------------------------------------

// (Return with a function) 
const distanceWalkedMilesArr = [140, 153, 161, 153, 128, 148]
const conversionFactorMilesToKm = 1.6

function convertMilesToKms() {
    return distanceWalkedMilesArr.map(function (distanceMiles, index) {
        return `Month ${index}: ${distanceMiles * conversionFactorMilesToKm}KM`
    })
}
console.log(convertMilesToKms())
```
- We can have access to the index similar to `forEach()` 
- The best thing about `.map()` is that it returns an array, in fact don't use it if you won't be using that new array

| .map()                         | .forEach()                      |
| ------------------------------ | ------------------------------- |
| if you will use that new array | If you don't need the new array |

### .join()
- It's best for creating strings from arrays, it actually works as a compliment to the `.map()` method :
	- So it concatenates elements of an array into a string
	- We can choose how elements are separated :
		- `<array>.join('<your seperator>')` it can be a space, comma, point, or *just empty string* 
	- It returns the new string
- Syntax : `<array>.join()` 

### .filter()
- It's used to filter array data using a given condition : it returns true or false
- Something we can do is : if the condition is true we can push that element to a new array
- Syntax : `<arrat>.filter(function(name_for_current_element) { <condition_or_code> })`
- EXAMPLE :
```
const ages = [1, 5, 9, 23, 56, 10, 47, 70, 10, 19, 23, 18]
const adults = ages.filter(function(age){
    return age >= 18
})
// now adults will contain only the elements greater than or equal to 18
```

### .reduce()
- All it does is it gives you just one thing, it's all about reducing 
- Syntax :
```
const <name_of_var_for_what_it_will_return> = <array>.reduce(function( <total>, <current_element> ) { <code> } )
```
- So at start : `total` will equal to the first element of the array, and `current_element` will equal to the second element of the array
- Then `.reduce()` will apply the code to these params, and then `total` will equal to the second element of the array and `current_element` will equal to the third element of the array And so on

- When working with Objects :
	- `.reduce()` takes actually 2 params : the first one is the function, and the second is the initial value of `<total>`
	- The second param is optional

### Normal For Loops
- Even though we have all of these methods and special for loops , a normal `for Loop` sometimes is the way to go mainly because of the option to use :
	1. `continue`
	2. `break`

### Various Array Methods
#### .every()
- Syntax : `<array>.every(function(name_for_current_element) { <code> })`
- Returns a Boolean value  :
	- It returns `true` if EVERY item passes the test (code)

#### .some()
- Opposite of `.every()` 
- Same syntax as `.every()`
- Returns a Boolean value  :
	- It returns `true` if one or more items passes the test (code)

#### .find()
- Finds the first item that passes the test (code)
- Returns the item itself
- Same syntax
- If we want the item's index we can use : `.findIndex()` 

#### .at()
- Used to get an item in an array at a position
- Syntax : `<array>.at(<number_even_if_it's_negative>)` : like python

### .replace()
- Used to replace something in a string with a given pattern
- Syntax : `<array>.replace( '<pattern>', '<replacement>' )`
- Only replaces the first Instance of that pattern
- To replace all of the patterns : `.replaceAll()`

- Sometimes we want to replace let's say only standalone `i` to uppercase `I` here to make sure that we don't change `i`s that are in words we use `Regex` : sequence of char that specifies a match pattern in text : `AI is good at creating it` so that's what you'll use in such case

- The second param `<replacement>` can be a function (for complex logic) with a param : the match of the pattern

## Function Expressions & Parameters
### Function Expressions
- Similar to how you declare a normal function but we store it in a const variable :
```
const <name> = function( <params> ) {
	<code>
}
```
- They are cleaner (arguably)
- They are not hoisted : you can't call them before they're declared (unlike normal functions)
- They depend on everyone's style

### Arrow functions
- Syntax : `(<params>) => { <code> }`
- If you have exactly 1 param you don't need the `()` 
- They are also stored in a const :
```
const <name> = ( <params> ) => {
	<code>
}
```
- We can also have this :
```
const <name> = ( <param> ) => < 1_line_code >
// Here there is no need for `return` or `{}` 
```

### Default params
- Let's say our function takes a param or 2 ... we can set a default value to that param that if we don't pass the param the default value will be used
- Syntax : `function( <param> = <default_value> ) { <code> }`

### The Rest param
- It's a way of catching the rest of the arguments
- It's used when we don't know how many arguments will be passed to our function
- It stores those arguments inside an array : which means we can iterate through them
- Syntax : `function( <param>, ...<restParam>) { <code> }`

- EXAMPLE :
```
function setPermissionLevel(permissionLevel, ...names) {
    names.forEach((name) => console.log(`${name} now has ${permissionLevel} level access.`))
}
setPermissionLevel('admin', 'Dave', 'Sally', 'Mike')
```
- The rest param must be the last parameter, and there can be 1 per function

### Callback functions
- Are functions that are passed to other functions :
	1. Like in `.map()` etc.
	2. Event listener
	3. etc.

## Async JS and APIs
### APIs
- Stands for : `Application Programming Interface` 
- You know what an API is (Talking to myself here) : It's like a intermediate that let's your program and someone else's program communicate 
- We used an API before actually : `.getElementById`  etc.
- Here is a place to see a lot of available Web APIs : [mozilla API Doc](https://developer.mozilla.org/en-US/docs/Web/API)

### Clients & Servers
- `Client` : is any device that connects to the internet to get data : He makes the `request`
- `Server` : computer that accepts requests and sends a response back to the user (usually in JSON data)
- JSON stands for : `Javascript Object Notation`

### URL and Endpoints
- URL is the base, and endpoint is the specific thing i want :
	- `https://voidpacket.com/about` : here `/about` is the endpoint and `https://voidpacket.com` is the base URL 

### fetching with .then()
- It's used to fetch for data from an API, it's old but still used today
- Syntax :
```
fetch( 'URL_TO_FETCH_FROM' )
	.then( response => response.json())
	.then(data => <code> )
```
- So what is `.then()` : it's a method that will pick up what we get from `fetch()` and make available to us in a param in a callback function which we usually call `response`
- The `.json()` method takes the JSON data that we got and transforms it to `Javascript Object` 
- NOTE that APIs don't always return JSON data (read the Doc of that API to know)
- So if we go back to those `.then()` we can see that each result of the previous line code gets passed to the next line of code :
	1. The result of `fetch()` goes to the first `.then()`
	2. The result of the first `.then()` goes to the second `.then()`
	3. And so on

### Fetching with async/await
- This is the Modern way
- Syntax :
```
const response = await fetch( 'URL_TO_FETCH_FROM' )
const data = await response.json()
```
- In the HTML we have to add the following in the `<script> tags` :
	- `type="module"` 
	- Or we can put our code inside a function (The most used way) and we add `async` in front of the function 
		- `async function <name>() { <the fetching code> }`

- Here the `await` is like we're saying wait till we get the response from the API then store it in  `const response`, and same thing with `const data` : wait till we store the result in `response` then do `.json()` and store it in `const data`

### Promises
- As the name suggests, `Promises` are just a promise that you will get a response : doesn't mean we'll get the data (just a response), due to that Promises have 3 states :
	1. Fulfilled
	2. Pending
	3. Rejected
```
e.g. : Job interview > 
	Once the interview is done they usually say we will get back to you within let's say a week.
	Here they only promise you a response not necessarily that you got the JOB.
```
#### Handling Rejected Promises
- We've seen how to handle fulfilled and Pending promises, now to the rejected ones : they're usually because an error occurred or something
1. We use `.catch()` method with the old fetching way (`.then()`)
	- Syntax :
	  ```
	  .catch( err => { <code> } )
	  ```
	- Something that we can add is : `.finally( () => { <code> } )` : it doesn't have anything to do with error handling, just it's a good thing to know : it runs at the end of the async operation (whether the promise is fulfilled or rejected)
2. We use `try ... catch` blocks with the Modern fetching way (`async/await`) 
	- Syntax :
```
try {

	// code we want to try to execute
	
} catch(err) {

	// code to execute on an error
	
} finally { // OPTIONAL

	// code to execute at the end of the operation
	
}
```

### response.ok
- The response const has a method called `.ok` that holds a `Boolean` value 
- It's used to check the HTTP response status : `false` or `true` 
```
if (!response.ok){
        throw new Error('There was a problem with the API')
}
```


### More On APIs
- So far we only used one HTTP method : `GET` used to get data
- So actually `fetch()` takes another param : an Object where we specify a lot of stuff > one of them is the HTTP method, by default it's `GET` 
```
fetch( 'URL', {method: 'GET'} )
```
#### POST Method
- With post we have to specify what we want to Send :
```
fetch( 'URL', {
	method: 'POST',
	body: JSON.stringify({
		<data>
	})
})
```
- `JSON.stringify` is used to transform `JS Objects` to `JSON` 
- With our request, we are sending a bunch of `Headers` which contain a lot of info : Content-Type, meta data etc.
- We can add our own headers inside the 2nd param of `fetch()` like this :
```
headers: {"Content-Type": "application/json"}
```

```
{
	method: 'POST',
	body: JSON.stringify({
		title: 'Holiday Nightmares',
        body: 'When I was kidnapped in Scotland…',
		userId: 100
	}),
	headers: {"Content-Type": "application/json"}
})
```

### Promise Constructor
- Used to build our own Async actions
- Syntax :
```
const promise = new Promise((resolve, reject) => {
	<code> e.g. :
	const success = Math.random() > 0.5
	if (success) {
		resolve('Operation successful')
	} else {
		reject('Operation failed')
	}
}) 
try {
	const response = await promise
} catch(err) {
	console.log(err)
}
```
#### Working with images asynchronously
- Instead of creating images this way :
```
const image = docunemt.createElement('img')
image.src = "http://........"
```
which tries to load the image before it reaches the DOM
- We can use the `Image()` constructor which loads the image only when it's in the DOM () :
```
const image = new Image()
image.src = "http://......"
```
- This is the best way, and it's the way you should be doing it as well

- Real WORLD example :
```
function preLoadImg(url) {
  return new Promise( (resolve, reject) => {
    const img = new Image()
    img.src = url
    img.alt = "a beautiful scene"
    img.addEventListener('load', ()=> resolve(img))
    img.addEventListener('error', ()=> reject('img has NOT loaded'))
})
```

### Callback Hell
- A situation where *multiple async operations are chained together using nested callbacks* which makes the code difficult to read and maintain
- EXAMPLE :
```
function uploadFile(callback){
    console.log('Step 1: Uploading file...')
    setTimeout(()=> {
        callback() // call next function
    }, 1000)
}

function processFile(callback){
    console.log('Step 2: Processing file...')
    setTimeout(()=> {
        callback() // call next function
    }, 1000)
}

function notifyUser(callback){
    console.log('Step 3: Notifying user...')
    setTimeout(()=> {
        callback() // call next function
    }, 1000)
}


/// HERE IS THE PROBLEME : 

uploadFile(()=> {
    processFile( ()=> {
        notifyUser( ()=> {
            console.log('All steps completed!')
        })
    })
})
```
- Here is where Promises saves us from this :
```
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


/// MUCH BETTER :

try {
    await uploadFile()
    await processFile()
    await notifyUser()
    console.log('All steps completed!')
} catch(err) {
    console.log(err)
}
```

### Promise.all
- It's used when we want to execute multiple promises concurrently, so the result : is either they all resolve or the catch block gets triggered.
- Also the OUTPUT of the `Promise.all` is an ARRAY.
```
const result = await Promise.all([promise1, promise2, promise3])
```

## Logical Operators & Coalescing
### Short-circuiting
- It's basically like `if else` but it's more concise and neater
#### with || (OR)
- Syntax : `const <name> = <condition result if true> || <condition result if false>`
- The result will be the first ***truthy condition***
```
const jobHunter = {
    name: 'Tom Chant',
    jobSearchArea: 'Europe',
}

const workLocation = jobHunter.jobSearchArea || 'Worldwide'

console.log(`${jobHunter.name}'s work location is ${workLocation}`)
```
#### with && (AND)
- If the code on the left is true the code in the right will run :
```
const user = {
    userName: 'Tom',
    role: 'admin',
}

user.role === 'admin' && console.log('Dashboard Displayed')
```
- And if the code in the left is false the code in the right won't run 

### Nullish Coalescing
- Syntax : similar to `||` and `&&` but with `??`
- It's very similar to `||` but the right side code runs only if the left side code is equal to : 
	1. `null`
	2. `undefined`
- Unlike `||` that will run it as long as the left side is falsy

### Optional Chaining
- It's used with complex objects :
```
const library = {
    sections: {
        fiction: {
            genre: {
                fantasy: [
                    { title: "The Hobbit", author: "J.R.R. Tolkien", year: 1937 },
                    { title: "A Game of Thrones", author: "George R.R. Martin", year: 1996 }
                ],
                scienceFiction: [
                    { title: "Dune", author: "Frank Herbert", year: 1965 },
                    { title: "Neuromancer", author: "William Gibson", year: 1984 }
                ]
            }
        }
    }
}
```
- It's a pain to go deep into this object and access an element's value, so we can use *Optional Chaining*
- Syntax : `?.` 
- Now we can handle errors : undefined, the possibility that one of the parent objects doesn't exist etc.

## Working with Objects
### Inbuilt methods
- We use Static methods :
	- Unlike Array methods which are built into the array, Object methods are built into the constructor
	- Syntax : `Object.<method>(<our_object>)` 
#### .keys()
- It's used to access the keys of an object :
	- `Object.keys( <object> )` 

#### .values()
- Used to access the values of keys of an object :
	- similar syntax to keys

#### .entries()
- `Object.entries` returns an array of arrays, where each inner array contains two elements: the key and the value of each property in the object.

- EXAMPLE :
```
Challenge :
	1. Use Object.entries to create an array from 'books'.
	2. Use an array method to filter out the books
     which cost less than 16.
	3. Iterate over the remaining books and log a string
     for each book in this format:
     ID: b001 Book: To Kill a Mockingbird £18.99
```

```
const books = {
  "b001": { title: "To Kill a Mockingbird", price: 18.99, isAvailable: true },
  "b002": { title: "1984", price: 15.99, isAvailable: false },
  "b003": { title: "The Great Gatsby", price: 12.49, isAvailable: true },
  "b004": { title: "Moby Dick", price: 22.50, isAvailable: false }
}

const bookEntries = Object.entries(books)
const remainingBooks = bookEntries.filter(([id, data]) => {
  return data.price >= 16
})

remainingBooks.forEach(([id, book]) => {
  console.log(`ID: ${id} Book: ${book.title} £${book.price}`)
})
```

### .hasOwn() and .hasOwnProperty()
- used to know if an Object has a property, `hasOwn()` is the new one
- They return a Boolean
#### .hasOwnProperty()
- Syntax :
```
<object>.hasOwnProperty(' <property_to_check_for> ')
```

#### .hasOwn()
- This is a static method
- Syntax :
```
Object.hasOwn( <object>, ' <property_to_check_for> ' )
```


- You SHOULD always use `hasOwn()` 

### Assignment by Value/Reference
- So for ARRAYS and OBJECTS when we reassign them to a new variable we are doing it with reference not with value (Remember that C/C++ stuff), so we don't actually make a new copy of that array or object, any change done in the new variable will be reflected in the old variable since it's the same array/object
- There are 2 levels of copying arrays and objects in JavaScript
![[Screenshot 2026-03-29 201540.png]]

### Spread Operator (...)
- It's used to expand and join arrays and much more, it's a bit hard to explain what can be done with it
- The syntax is similar to the REST operator (...) which can cause confusion
- EXAMPLE
```
const lunchMenu = ['Greek Salad', 'Open Sandwich', 'Parsnip Soup', 'Flatbread and Dip']

console.log(...lunchMenu)
// Greek Salad,"Open Sandwich","Parsnip Soup","Flatbread and Dip"

console.log(lunchMenu)
// ["Greek Salad", "Open Sandwich", "Parsnip Soup", "Flatbread and Dip"]
```

- You can see here what the Spread operator does : we don't have the `[]` anymore which is just powerful, which means it's no longer an array
- We can do something like : `const array = [...oldArray]` just like that we have made a ***COPY*** of an array : a ***SHALLOW COPY*** to be exact

- We can join arrays together like this :
```
const lunchMenu = ['Greek Salad', 'Open Sandwich', 'Parsnip Soup', 'Flatbread and Dip']
const dinnerMenu = ['Lasagne', 'Strogonoff', 'Tagine', 'Katsu Curry']
const sweetMenu = ['Mixed Berry Ice Cream', 'Chocolate Brownie', 'Orange Cheesecake']

const eventMenu = [...lunchMenu, ...dinnerMenu, ...sweetMenu]
```

- NOTE: the same thing can be done with OBJECTS :
```
const salad1 = {
    name: 'green',
    ingredients: ['lettuce', 'tomato']
}
const salad2 = {...salad1}
```

### Object.assign()
- It's a way of making a SHALLOW copy of an Object
- Syntax :
```
Object.assign( <Where_to_copy> , <What_to_copy> )
```

### structuredClone()
- Used to make a DEEP copy
- Syntax :
```
const deepCopy = structuredClone( <Original_Object> )
```

### The 'this' keyword and Object methods
- Functions that are stored in an object and can be used by that object are called `Methods`
```
const gamer = {
    name: 'Dave',
    score: 0,
    incrementScore: function(){
        gamer.score++  
    }
}

gamer.incrementScore()
```
- But this is not the best way to create methods, because if the object's name changes we have to also change it everywhere we used it, that's why we have the `this` keyword
```
const gamer = {
    name: 'Dave',
    score: 0,
    incrementScore: function(){
        console.log(this)  
    }
}

gamer.incrementScore() // IT WILL LOG THE WHOLE OBJECT 
```
- So it's like it references the Object
- Now we create our methods like this :
```
const gamer = {
    name: 'Dave',
    score: 0,
    incrementScore: function(){
        this.score++  
    }
}

gamer.incrementScore()
```

- NOTE : We use anonymous functions and not arrow functions because arrow functions deal with the `this` keyword a bit weirdly, so always use anonymous functions 
- Now this might not sound amazing, but what if we have 50 or 100 gamer objects, our code won't be DRY : the `incrementScore` method will be repeated in all of them

### Binding 'this'
- So most of the time we would store methods in variables, but when using `this` it will actually give us an error :
```
const product = {
    name: 'Vanilla Lip Gloss',
    sku: 'w234fg',
    stock: 276,
    getProductInfo: function() {
        console.log(this)
    }
}

const productDetails = product.getProductInfo
productDetails()

/// THIS WILL GIVE AN ERROR
```

```
THIS : const productDetails = product.getProductInfo
IS EQUIVILANT TO THIS :
const productDetails = function() {
	console.log(this)
}
```
- The problem is that here : `this` is undefined, to define it we use the `.bind()` method 

- SYNTAX : `<object>.<method>.bind( <object> )`
```
const product = {
    name: 'Vanilla Lip Gloss',
    sku: 'w234fg',
    stock: 276,
    getProductInfo: function() {
        console.log(this)
    }
}

const productDetails = product.getProductInfo.bind(product)
productDetails()
```


- NOTE :
	- If `this` is used in an event listener, `this` refers to the element that triggered it


## Creating Custom Objects
- So let's take this example where we need to store data of employees, it will be stupid to do it manually (what if we have 200 employees) so what we do : 
	- We pass our Object template (how we want the data to be stored and presented)
	- And we pass the employee's data 
	- Then we get back the Completed Object 
- We have 3 ways to do that :
	1. Factory Functions : basic 
	2. Constructor Functions 
	3. Classes : it's easy when things gets complex 

### Factory Functions 
- It's just a normal functions that returns an Object
- Syntax :
```
function gamer(name, score) {
    return {
        name: name,
        score: score,
        incrementScore() {
            this.score++
        }
    }
}

const alice = gamer('Alice', 10)
alice.incrementScore()
```

- So again it's a normal function, we're using familiar syntax


| Pros            | Cons            |
| --------------- | --------------- |
| Familiar syntax | Less Performant |
| easy to read    | No Inheritence  |

### Constructor Functions
- The syntax is similar to a normal functions, but the first letter of the Name has to be UPPERCASE, and we use the keyword `this` instead of normal Object syntax :
```
function Gamer(name, score) {
    this.name = name
    this.score = score
    this.incrementScore = function() {
        this.score++
    }
}

const dave = new Gamer('Dave', 0)
dave.incrementScore()
```

### Classes
- It's a special kind of function that works as a template for creating Objects
- Syntax :
```
class <name_with_uppercase_first_letter> {
	
	// to set up our object we use 'constructor()' keyword
	
	constructor( <properties> ) {
		<This is where we initialize the Object>
	}
	
	// For any methods : we call them like a normal function
	<name>() {
		<code>
	}
}
```

EXAMPLE :
```
class Gamer {
    constructor(name, score) {
        this.name = name
        this.score = score
    }
    
    incrementScore() {
	    this.score++
    }
}
```

- Now there is not much difference between `classes` and `constructor functions` so use what you like
- ***NOTE*** : *Pro Devs don't create objects like this anymore, they tend to use frameworks like `React` etc. so you won't need to have a deep understanding of this*

## Inheritance 
### .call() and .apply()
- These are JS methods, that allow us to control the value of `this` when invoking functions :
	- So we've seen that `Objects` have the keyword `this` , well *functions* DO TOO
#### .call()
- When we have a function and we want to pass an Object's properties as an argument, we can do that using `.call()` :
```
<function>.call(<object>, <any_other_necessary_arguments>)
```

- NOTE : those properties when used inside that function need to start with `this.<the_property>`
EXAMPLE :
```
function displayPolitician(currentSituation) {
    console.log(`${this.name} is ${this.age} years old. Current situation: ${currentSituation}.`)
}

const politician1 = {
  name: 'Carly Fowler',
  age: 40
}

displayPolitician.call(politician1, 'In jail for corruption')
```

- So which means `this` represents that `Object` : if you log `this` inside that function it will return the Object

#### .apply()
- The only difference is the `<any_other_necessary_arguments>` needs to be an ARRAY :
```
<function>.apply(<object>, <any_other_necessary_arguments>)
```

- NOTE : That ARRAY will be destructed, so we can use each param individually

### Inheritance
- It's the mechanism by which objects inherit properties and methods from other objects
- So let's say we have a parent Object (`baseEvent`) which will have some properties (`name, date, location, getDetails`) now we want every child Object (`concert`) to inherit these properties : That's how it works.
- This forms what's known as : `PROTOTYPE CHAINE`
	- It simply means that if an object B is a prototype of object A, it can inherit from object A, and if an object C is a prototype of B, it can inherit from B and indirectly inherit from A
	- The First Object that isn't a prototype of an object actually is a prototype of `Object` : JS's base Object, which is referred to as `Object Object`
- So when you try to look up for a method or property : JS checks if it exists in the current object then it keeps moving up the ladder of prototypes till it finds it or it till it reaches the end
### Polymorphism
- It allows properties and methods to get repurposed to meet that exact Object's needs : so the object inherits a method/property and override it's value or functionality 

### Inheritance with Constructor functions
- This is the old way, it's not that good but it's good to know about it :
- You basically have to add these 3 lines
```
// Inside the child constructor you add this :
<parent_constructor>.call(this, <other_params_the_parent_takes>)

// outside :
<child_constructor>.prototype = Object.create(<parent_constructor>.prototype)
<child_constructor>.prototype.constructor = <child_constructor>
```

- NOTE : the child constructor has to also take the parent's params 
### Polymorphism with Constructor functions
- So instead of doing it the normal way : 
```
// This inside the parent constructor
this.<name_of_method> = function() {}
```
which will be resource intensive, it's better to create it in the prototype of the constructor :
```
// this outside it
<parent_constructor>.prototype.<name_of_method> = function() {}
```

- Now to override the method inside a child constructor :
```
// Outside the constructor
<child_constructor>.prototype.<method_name> = function() {
    const <name> = <parent_constructor>.prototype.<method_name>.call(this)
}
```

### Inheritance with Classes
- It's the best, modern way to do this 
```
class <child> extends <parent> {
	constructor( <params of parent + child> ) {
		super( <params of parent> )
		
		<rest of code>
	
	}
}
```

- The `super()` keyword does 2 things :
	1. Access properties on the superclass's prototype
	2. Invoke the superclass' constructor

### Polymorphism with Classes
- Again very simple, all we do is add the `super` keyword
```
class <child> extends <parent> {
	constructor( <params of parent + child> ) {
		super( <params of parent> )
		<rest of code>
	}
	
	
	<method_name>() {
        const <name> = super.<method_name>()
        
        <rest of code>
        
    }
}
```

## Static Methods and properties
- the `static` keyword defines methods and properties that belong to the class itself rather than to instances of the class. They are accessed directly through the class name
- Syntax : `static <name_of_method_or_property>` 

## Private Fields
- Used to protect properties : we cannot change their value
- Syntax, we add `#` at the beginning : 
```
// let's make destination private

class Holiday {
    #destination
    constructor(destination, price) {
        this.#destination = destination // since we want to assign it using a param we added this, but we can assign it in the first declaration 
        this.price = price
    }
}  
```

### Getters and Setters
- To get the value of private properties we use `getters`
```
// inside the class we add a method 

get <name>() {
	return this.#<name_of_private_property>
}

// then you call this method like you would normally do
```

- `setters` are used to modify the private property
```
// inside the class we add a method 

set <name>() {
	<code>
}
```

## Symbols, Collections
### Symbols
- It's a primitive Data type
- Each symbol is unique (similar to UUIDs)
- Syntax : `const <name> = Symbol('<description>')`

### Map Object
- It doesn't have anything to do with the `map()` method
- It holds Key value pairs with benefits :
	- Keys can be of any data types
	- Iterate over it with a `forEach`
	- Insertion Order
- Syntax :
```
const <name> = new Map()
// you add key value pairs like this :
<name>.set(key, value)

// to get a value to a corresponding key : 
<name>.get(key) 

// we can get the size :
<name>.size

// to delete a key value pair :
<name>.delete(key)

// to check if a key exists :
<name>.has(key) //returns a boolean

// to iterate with forEach :
<name>.forEach( (value, key) => {} )
```

### Set Object
- Object that stores unique values (no duplicates, and only values so like an array) 
- So which means we can use it to remove duplicates 
- Syntax :
```
const normalArray = ['shoes', 'after shave', 'tesla', 'after shave', 'shoes']

const setArray = new Set(normalArray)
```

- We can iterate with `forEach`, also we don't have access to all array methods, so if we want to have access to them we have to transform it back to a normal array
```
const setArray = Array.from(new Set(normalArray))
```

- We can `add` `delete`, check if it contains something with `has` and we can clear it with `clear()` 
	- `setArray.add( <something> )`
	- `setArray.delete( <something> )`
	- `setArray.has( <something> )`
	- `setArray.clear()` 

## Advanced Function patterns and generators
### Closures
- No clue what benefit they have, they seem unnecessary

### Immediately Invoked Function Expressions (IIFEs)
- These are functions that run without being invoked : they run at the beginning of a session 
- Syntax :
```
(function() {}) ()

OR 

(function <name>() {})
<name>()

```
- The syntax is the same even if you have params or if it's an `async` function

### Recursion
