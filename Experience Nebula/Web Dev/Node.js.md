# GoldDigger Project
- I learned so much with this project: simple yet challenging, after i finished the course i thought i can do this very easily: hhhhhhhh. Well it wasn't.

## What I've learned :
### What almost every project need :
```
/my-app
├── /public (The "Dining Area")
│   ├── index.html, index.css, script.js
├── /utils (The "Kitchen Tools")
│   ├── sendResponse.js (The Waiter)
│   ├── getContentType.js (The Label Maker)
├── /services (The "Prep Stations" - New Concept)
│   ├── logger.js (The Clipboard for JSONL)
├── /handlers (The "Chefs")
│   ├── formHandler.js (The "Chef" who processes the Gold)
│   ├── staticHandler.js (The "Pantry Manager" serving files)
└── server.js (The "Kitchen Manager" / Traffic Cop)
```

### form tags can take endpoints and methods
```html
<form action="/submit-amount" method="POST">
```
- **`action="/submit-amount"`**: This is the **address**. It tells the browser, "When the user clicks the button, take all the data inside this form and deliver it to this specific URL on the server.
- I know i could've simply used `fetch` but i was confused okey hhhhhh i didn't know what to do, or how to know if the button was clicked or how to send that amount chosen to the server 

- to get that data to my server i used the following:
	- When a form is submitted via `POST`, the data arrives at your server as a raw, messy string that looks like this:  
		- `"investment-amount=100&currency=GBP&user=John"`

	- The server doesn't automatically know that `100` belongs to `investment-amount`. It just sees one long text string.

1. `const params = new URLSearchParams(body)`
	- This line takes that messy string and turns it into a **Search Object**. It scans the text, finds the `equal`  and `&` signs, and creates a map of keys and values.
2. `const amount = params.get('amount')`
	- Now that you have an object, you can ask it questions.
		- **`.get('amount')`** tells the translator: "Look through the data you just parsed and find the value associated with the name **'amount'**."
		- This matches the `name="amount"` attribute you put on your `<input>` in the HTML.

### Use JSON instead of txt
- For better scalability it's best to use `.json`, this way you can get access to those data

- I used `req.on('close', clearInterval(intervalPrice))` :
	- `req.on()` is a method used to listen for **events** on an incoming HTTP request. 

