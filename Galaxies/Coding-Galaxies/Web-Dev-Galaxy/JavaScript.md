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
