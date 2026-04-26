# Note 1
- When we have a Parent container and we want to position the child element somewhere specific we add this CSS to the parent :
	- `display: flex;`
And then we add the `margin-top` , `margin-left` etc. and we set them to `auto` to the child, just NOTE that we have to use the opposite direction: 
- If we want to set it to the top left :
	- ```
	  margin-right: auto;
	  margin-bottom: auto;
	  
	  // OR USE this shortcut : margin: top right bottom left;  
	  ```
	  - This can be helpful with nav bars, menus ...
# Note 2
- Sometimes `elements` within `elements` will have a default `margin` which can cause some overflows, to deal with it Devs use :
  ```
*, *::before, *::after {
    box-sizing: border-box;
}
  ``` 
  - This ensures that any padding or borders you add don't accidentally make an element wider than you intended.
# Note 3
- *The following can be used to add a banner : element on top of an element*
## Position relative and absolute
- When using `position: absolute;` on an element it automatically ignores the fact that : that element is within a container 
- So if we want it to still be inside it's container, we have to make the container `position: relative;`
	- Now we can position that element wherever we want inside that container :
		- ```
		  // example (top left corner):
		  position: absolute;
		  top: 0;
		  left: 0;
		  ```
- When setting `absolute` the element will shrink to only take the space needed to hold it's content, if you want to counter that just add : `width: 100%;` or what value you want.
## Position fixed
- It's similar to `absolute` but with `fixed` scrolling doesn't hide it : it will always be visible 
```
// Example : making a div visible in the center like an Annoying Ad :

posistion: fixed;
top: 0;
bottom: 0;
left: 0;
right: 0;
margin: auto;
```
### z-index
- When using position we get the option to use `z-index: ;` which plays with the Z value of the element
- `z-index` 's default is `auto` which is equal to `0`, so when you don't use it, by default it's equal to `0`
# Note 4
- We can take control of a child element's alignment withing a flex display (`display: flex;`) using : `align-self: <position>;` 

# CSS Grid
- Grid is 2D unlike flexbox (1D)
- We can achieve complex layout with less HTML
- We have complete control over Order of elements
- etc.

## Gird Columns and Gap
- When we choose : `display: grid;` nothing changes visually but the following happens :
	1. Margins no longer collapse
	2. Elements in a grid container become a grid items
	3. Grid items fall into place on the grid
- One of the most used grid properties are :
	- `grid-template-columns: <values in fr> ;` which sets the width of column
	- You can add other values which will split the grid items into more columns :
		- `grid-template-columns: 1fr 1fr;` : this will make 2 columns where they have a width equal to a fraction of available width (50% in this case)
		- If we want it to just use the needed space for what it contains we can use `auto`
	- We will also use `gap: <between rows in em> <between columns in em> ;` 
	- We have : `grid-template-row: <values in fr> ;` which works with rows
	- OR BETTER just use `grid-template: <values of rows> / <values of columns> ;`

### Placing grid-items with span
- We can now specify where each grid item sits
- We use `grid-column: span <value without unit>;` or `grid-row` 
- NOTE : using the `span` won't allow us to change the layout in a way that doesn't match the HTML (hope it makes sense)
- We can also make a grid item stretch from start to end of the grid with : `grid-column: 1 / -1;` same thing for rows (Those numbers can be changed to specify what column or row number to start and to end at)
### Repeat function
- When using stuff like : `grid-template-columns: ;` we use a lot of for example `1fr` to not repeat it we use this: `repeat( <how many times> , <what to repeat> );` 
```
grid-template-columns: repeat(7, 1fr) auto;

this is equal to : 

grid-template-columns: 1fr 1fr 1fr 1fr 1fr 1fr 1fr auto;
```

### grid-template-areas
- This is another way to place items in a GRID
- I really don't like it so am not gonna explain it 