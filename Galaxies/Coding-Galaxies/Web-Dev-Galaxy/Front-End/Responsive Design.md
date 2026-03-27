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

# Note 3
- `rem` it uses the root size as reference always
- `rem` are recommended to use more that `em`

# Note 4
- line-height doesn't need a specify `unit` you can simply not use one :
	- `line-height = 2;`


| Property | font-size | margin & padding | line-height | width | max-width |
| -------- | --------- | ---------------- | ----------- | ----- | --------- |
| Unit     | rem       | em               | unitless    | %     | px        |

# Note 5
## Media Queries
- Allow us to modify our layout depending on the width of the screen : mobile, pc, laptop etc.
- Syntax :
  ```
  @media ( < width (max or mix) > ) {
	  <CSS properties to apply for that specific width>
  }
  ```
- They're like if statements : if the width of screen is `800px` use this CSS
- EXAMPLE :
```
@media (min-width: 480px) {
    .section-two-image-container {
        flex-direction: row;
        justify-content: space-between;
    }
    .feature-image {
        width: 48.8%;    
    }
}
```

## Mobile first 
- One of the most used approaches is : **Mobile First**, which means design for mobile (small screens) first then scale up
- This is because Mobile users > Desktop users, also it's easier to go from small screens to wider screens in CSS
- You will need to show content first : NO EXTRA

- So you might be wondering what sizes i should be targeting in my media queries, there is no standard but here is something :
	1. <= 480px
	2. 768px
	3. 1024px
	4. >= 1280px 
- So what Devs would do is try to resize the layout until they find a layout where something breaks 
- [Learn more](https://developer.chrome.com/docs/devtools/device-mode/) 

## Buttons
- It is common to set buttons in small screens as a block (taking the whole row)

## Font
- Don't forget to also scale down the font-size

## Meta tag
- This is the most crucial thing to add in your HTML :
```
<meta name="viewport" content="width=device-width, initial-scale=1.0">
```
- Paste it in the `head` tag

## Flexbox image grid
- We can have a responsive image grid layout using these flexbox properties :
	1. `flex-basis` : like `width` sets the original size
	2. `flex-grow` 
- EXAMPLE :
```
.image-container {
    max-width: 800px;
    line-height: 0;
    margin: 0 auto;
    display: flex;
    flex-wrap: wrap;
    border: 2px solid;
}

.pet-item {
    flex-basis: 220px;
    flex-grow: 1;
}
```
- We also have a shortcut that mixes them both :
	- `flex: <grow> <basis>`
- 