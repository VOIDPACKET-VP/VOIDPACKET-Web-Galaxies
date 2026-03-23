- We use Relative Units (e.g. em, %) not absolute (e.g. px)

# Note 1
- When using `%` on `width` : the percentage is based on the width of the parent element : this can be helpful when making stuff like `progress bar` etc.
- `%` are mostly used with `widths` 

# Note 2
- We use `max-width` to set well a max width that the elements won't surpass 
- Similar thing with `min-width` (it's not commonly used)

# Note 3
- There is the `em` unit which is mainly used for Text and it is based to the parent element :
	- `1em` is equal to the parent element's font-size value 
		- You can think of it like this : `<value> * inherited font size`
- If you have a desired size but it's in `px` you can convert it to `em` with this formula :
	- `desired size (in px) / inherited font-size` = `desired size (in em)`
- We can also use `em` with `padding and margin` and it takes the font-size of that element as a base
- 