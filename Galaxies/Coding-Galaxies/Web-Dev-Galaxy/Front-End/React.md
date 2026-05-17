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

