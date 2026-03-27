# Note 1
- When we have a Parent container and we want to position the child element somewhere specific we add this CSS to the parent :
	- `display: flex;`
And then we add the `margin-top` , `margin-left` etc. and we set them to `auto` to the child, just NOTE that it we have to use the opposite direction: 
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
* {
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