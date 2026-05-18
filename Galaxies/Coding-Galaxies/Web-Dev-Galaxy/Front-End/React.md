# How to setup react locally
- We will use a build tool called : `Vite` 
- We need to have `node` and `npm` installed so check by using these commands :
	- `node -v` and `npm -v`
- Then use : `npm create vite@latest`
	- Answer some stuff
	- Choose `react` 
	- Then it will give you the some commands that you need to follow

# Let's begin
- So you know when you want something to show on your website you have to add it to the HTML, Well `React` will take care of that by taking our `Javascript` and add the associated `markup (HTML)` to our HTML
	- But in order for that to work : we have to add a placeholder in our HTML so that React knows where to put things :
		- `<div id="root"></div>` 

> Note : The javascript file's extension will no longer be .js it will be .jsx

# Simple React setup
```js
import { createRoot } from "react-dom/client"

// 1. Create a root
const root = createRoot(document.getElementById("root")) 

// 2. Render some markup to the root
root.render(<h1>Hello, React!</h1>)
```

- So you can see that we can write HTML like code in JS, how does it work? `createElement()` 
	- It's a react function that returns an object that react understands 
```js
import { createElement } from "react" 
import { createRoot } from "react-dom/client"

const root = createRoot(document.getElementById("root"))
const reactElement = createElement("h1", null, "Hello from createElement!")

console.log(reactElement)
root.render(reactElement) // this will render normally
```
- the console.log will return this :
```js
{type: 'h1', key: null, props: {children: 'Hello from createElement!'}, _owner: null, _store: {}}
```

# JSX
- It's what react uses to make us write html in javascript : we don't have to use `createElement` or anything

# Components
- So one thing about react is that it's composable, you can create something and use it with a different purpose somewhere else : it's called `components` 
- EXAMPLE : if you want to have a navbar, usually you would add it to every HTML page you have in your project, you want to change something in it? you have to do it in all of them, see the problem
	- But with React components you can create it once, and use it anywhere, how? :
		1. You do it inside a function : first letter must be capital
		2. The function returns your component, it's better to wrap it (component) inside `()` 
		3. Render it : inside `root.render()` you add this `<YourComponent />`, followed by your other components if you have them

```jsx
import { createRoot } from "react-dom/client"
const root = createRoot(document.getElementById("root"))

function MyAwesomeNavbar() {
    return (
        <nav className="navbar navbar-expand-sm navbar-dark bg-dark" aria-label="Third navbar example">
            <div className="container-fluid">
                <a className="navbar-brand" href="#">MyAwesomeNavbar</a>
                <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarsExample03" aria-controls="navbarsExample03" aria-expanded="false" aria-label="Toggle navigation">
                    <span className="navbar-toggler-icon"></span>
                </button>
                <div className="collapse navbar-collapse" id="navbarsExample03">
                    <ul className="navbar-nav me-auto mb-2 mb-sm-0">
                        <li className="nav-item">
                            <a className="nav-link active" aria-current="page" href="#">Home</a>
                        </li>
                        <li className="nav-item">
                            <a className="nav-link" href="#">Link</a>
                        </li>
                        <li className="nav-item">
                            <a className="nav-link disabled" aria-disabled="true">Disabled</a>
                        </li>
                        <li className="nav-item dropdown">
                            <a className="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown" aria-expanded="false">Dropdown</a>
                            <ul className="dropdown-menu">
                                <li><a className="dropdown-item" href="#">Action</a></li>
                               <li><a className="dropdown-item" href="#">Another action</a></li>
                                <li><a className="dropdown-item" href="#">Something else here</a></li>
                            </ul>
                        </li>
                    </ul>
                    <form role="search">
                        <input className="form-control" type="search" placeholder="Search" aria-label="Search" />
                    </form>
                </div>
            </div>
        </nav>
    )
}

root.render(
    <div>
        <MyAwesomeNavbar />
    </div>
)
```

> NOTE : when you want to render more than one element you must wrap them in a parent element : a div, a main whatever works.

# Fragment
- Remember the last note ^^^
- Well instead of adding a useless parent element what we can do is use `Fragments` they act the same way, the have the same purpose but when react sees them it doesn't create a useless HTML element
```jsx
import { Fragment } from "react"

function Page() {
    return (
        <Fragment>
            <header>
                <img src="react-logo.png" width="40px" alt="React logo" />
            </header>
            <main>
                <h1>Reason I am excited to learn React</h1>
                <ol>
                    <li>React is a popular library so I will be able to fit in with all the coolest devs out there! 😎</li>
                    <li>I am more likely to get a job as a front end developer if I know React</li>
                </ol>
            </main>
            <footer>
                <small>© 2024 Ziroll development. All rights reserved.</small>
            </footer>
        </Fragment>
    )
}

root.render(
    <Page />
)
```
- See those `<Fragment>` tags !!
- Another way is to not import them and instead of `<Fragment>` we use empty tags `<> </>`  

- In JSX, when we want to add a class for our element we don't do it like you would normally `class=""` but like this :
	- `className=""`

> Something you will start to do is : put each Component you make in it's own .jsx file, this way you won't clutter your main .jsx file (App.jsx) which gets imported to index.jsx to get rendered, then all you have to do is import and export it


# Props
- They are similar to function arguments, they help with composability
- EXAMPLES : YT videos (how they appear) that's something that's achieved with components and props : same structure different data

> NOTE : if you have variables and you want to include them in your JSX, you will have to put them inside {}, unlike JS where you put them inside ${}

## How to pass data (props)
- The way to do it is very simple, when you call the component `<Component />` you add your data like HTML attributes
```jsx
<Contact
	img="./images/mr-whiskerson.png"
	name="Mr. Whiskerson"
	phone="(212) 555-1234"
	email="mr.whiskaz@catnap.meow"
/>
```

## How to receive that data (props)
- In your component (the function declaration) you add one argument : after all props are equal to arguments (to my understanding) 
```jsx
function Contact(props) {
}
```

> Note if you log `props` you will get an object that has all of those prop data

```jsx
{img: './images/felix.png', name: 'Felix', phone: '(212) 555-4567', email: 'thecat@hotmail.com'}
```

- Now if you wanna use that data inside your `JSX` you have to do it like this 
	- e.g. `{props.img}`

## Destructuring props
- So props is an Object thus we can Destructure it
```jsx
const props = {
img: './images/felix.png', name: 'Felix', phone: '(212) 555-4567', email: 'thecat@hotmail.com'
}

const {img, name} = props
```

- This means we can destructure it inline 
```jsx
function Contact({img, name, phone, email}) {
	return (
		<h1>{name}</h1> //instead of {props.name}
	) 
}
```

### Non string props
- When your prop is not a string, you can use the `{}` 
```jsx
<Contact 
	phone={44651651561} 
/>
```


## React can render arrays
- We use the `.map()` method to well loop through the array and edit it, pass it to the component and render the component
```jsx
// We have imported this array :
/*
export default [
    {
        question: "I got my daughter a fridge for her birthday.",
        punchline: "I can't wait to see her face light up when she opens it."
    },
    {
        question: "How did the hacker escape the police?",
        punchline: "He just ransomware!"
    },
    {
        question: "Why don't pirates travel on mountain roads?",
        punchline: "Scurvy."
    },
    {
        question: "Why do bees stay in the hive in the winter?",
        punchline: "Swarm."
    },
    {
        question: "What's the best thing about Switzerland?",
        punchline: "I don't know, but the flag is a big plus!"
    }
]
*/


export default function App() {
    const jokeElements = jokesData.map((joke) => {
        return <Joke  
            setup={joke.setup}
            punchline={joke.punchline}
        />
    })
    return (
        <main>
            {jokeElements}
        </main>
    )
}
```

# Key prop
- Allows React to keep track of what data is this, and the order etc.
	- If you ever added functionality like deleting a post, adding it etc. React need that Key prop to keep track 
- so anytime you're transforming an array of data into an array of props you have to add a key prop
- SYNTAX :
```jsx
<Contact 
	key={somethingUnique}
/>
```
- It can be anything as long as it is unique to that exact instance

> Beginners will tend to use the index from .map() but it's generally a bad idea

> Note : there other ways to pass an object as a prop : `obj={myObject}` or `{...myObject}` just remember that you're prop naming must be the same as the naming in the object for this to work