
# indexof()
- It allows you to take control of an object using an index.
- If you want to like compare 2 objects' values using an array as a comparer, use the `indexof()` method.
- Example :
	const cardsValueArr = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "JACK", "QUEEN", "KING", "ACE"]
	function compareCards(card1, card2){
	    const index1 = cardsValueArr.indexOf(card1.value)
	    const index2 = cardsValueArr.indexOf(card2.value)
	    if(index1 > index2){
	        console.log("Card1 wins")
	    } else if (index1 < index2){
	        console.log("Card2 wins")
	    } else {
	        console.log("It's a tie!")
	    }
	}
- This is more useful when we the values are a mix of numbers and strings.

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



# Time 

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
	  `function getCurrentTime() {`
		    `const date = new Date()`
		`document.getElementById("time").textContent = date.toLocaleTimeString("en-us", {timeStyle: "short"})`
		`}`
	`setInterval(getCurrentTime, 1000)`

- We can use `setTimeout()` which executes code after a specified amount of time : `setTimeout(<function>, <time in ms>)`

# Short-circuiting, Nullish coalescing, and Optional Chaining

- They are a bit advanced JavaScript syntax, but very helpful, they allow you to make logic efficiently with less code .
## Short-circuiting 
- Syntax :
1. &&
	`const result1 = 0 && 'hello'; // result1 is 0 (0 is falsy, short-circuits)` 
	`const result2 = 'world' && 'hello'; // result2 is 'hello' ('world' is truthy, 'hello' is evaluated)`

2. ||
	`const result3 = 'world' || 'hello'; // result3 is 'world' ('world' is truthy, short-circuits)`
    `const result4 = '' || 'hello'; // result4 is 'hello' ('' is falsy, 'hello' is evaluated)`

## Nullish Coalescing
- Syntax :
  1. ??
	`const result5 = 0 ?? 'default'; // result5 is 0 (0 is not nullish, short-circuits)`
    `const result6 = null ?? 'default'; // result6 is 'default' (null is nullish, 'default' is evaluated)`

## Optional Chaining
- Syntax :
1. ?.
	`const user = {`
      `name: "Alice",`
      `address: {`
        `street: "123 Main St",`
        `city: "Anytown"`
      `}`
    `};`

    `const street = user?.address?.street; // "123 Main St"`
    `const zipCode = user?.address?.zipCode; // undefined (no error)`

## Iterate through an ARRAY :
- iterating over an array can be a bit tricky so here is a successful way :
	- Let's say we have an array called `data` :
		`for (const [key, value] of Object.entries(data)) { <rest of code goes here > }`

- This can help you go through input user and sanitize them for example

## How to turn Objects into Arrays
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