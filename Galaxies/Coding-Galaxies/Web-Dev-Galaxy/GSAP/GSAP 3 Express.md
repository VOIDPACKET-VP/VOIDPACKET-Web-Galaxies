# GSAP Objects
- So before in GSAP we use `tweens` and `timelines`, but now we have the `gsap objects {}`
- We have 3 methods to create tweens and optionally adding them to a timeline :
	1. `gsap.to()`
	2. `gsap.from()`
	3. `gsap.fromTo()`

- So a `tween` can change a single or multiple properties of a single object or objects over time, so we can do something like this : 
	- `gsap.to( ".star", {x:750, duration:3} );` which will translate the Object `star` 
	- Something to note is that the tweens have their own `playhead` : like the one you find in `Davinci Resolve` etc. and we can inspect where that `playhead` is at
	- A `tween` allows us to delay the animations of those objects 

- A `Timeline` is a container for multiple tweens : you can think of it the same way you think as you think of a real Davinci resolve timeline 

## Basic Tween
- Simple syntax : `gsap.to("<target>", {<properties>, <duration>})`
- NOTE : if you don't specify the duration it will be set to `500ms = 0.5s` 
- For best performance animate CSS transforms and Opacity
	- some of the properties are :
		1. `x` for x translation
		2. `y` for y translation
		3. `scale or scaleX, scaleY` 
		4. `fill` for color
		5. `staggered` to delay when the objects connected to the same Tween  start animating
		6. `rotation or rotationX, rotationY` 
		7. `skewX and skewY` 
- GSAP can animate any numeric property you throw at it.
	1. width and height
	2. backgroundColor ***hyphenated values need to be camelCase**
	3. color
	4. padding
	5. left and top (must set position to relative, absolute, or fixed)
	6. vh and vw

### Special Properties
- Special properties define how the animation should run and what it should do. Special properties are not animated
	1. **delay**: how much time should transpire before animation begins
	2. **repeat**: how many times the animation should repeat
	3. **yoyo**: when set to true the animation will play back and forth
	4. **repeatDelay**: how much time should transpire between each repeat
	- An animation will **repeat indefinitely** if you set **repeat:-1**
- We can also control the flow of the animation using `Ease` :

### to(), from() and fromTo()
- `to()` animates to the properties you set
- `from()` animates from the properties you set to the default values
- `fromTo()` allow us to set the starting values and the end values : 
	- `gsap.fromTo("target", {<starting_values>,<ending_values>})`
	- If you set a property in the `starting_values` and not add it's ending version in the `ending_values` it will not change : it stays fixed, but NOT VICE VERSA
