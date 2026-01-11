- This is really not all the basics but some of the "Advanced" basics 

## Random
- `\0` is called a *Null Buffer* 
- Sometimes when asking for user input, other inputs might get ignored by our C program because the `input buffer` is full even though we didn't enter anything, to counter that : 
	- If we're using `scanf();` we can just add a space before the `%c` or `%d` etc.
		- `scanf(" %c", &grade);`
	- If we're using `fgets();` we'll have to use a function called `getchar();` before the `fgets();`

## `#include <string.h>`
- It gives us a lot of functions related to working with strings :
	- `<string_variable>[strlen(string_variable) - 1] = '\0'` > `strlen()` gives us the length of a string



## Project Ideas

- The projects are organized from ***Beginner*** to ***Advanced*** :
	1. `Shopping Cart Program` : User chooses an item, sets a price and amount, the program returns the Total amount.
		- You can take it further by allowing the user to choose multiple items
		- You set the price
		- etc.
	2. ``