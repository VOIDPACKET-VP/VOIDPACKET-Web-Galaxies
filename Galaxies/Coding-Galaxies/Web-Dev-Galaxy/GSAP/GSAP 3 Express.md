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
	- By default the ease is set to : `ease out`
	- To modify we use the keyword : `ease: "<type>"` 
	- **`ease:”bounce”`** will bounce on the way out
	- **`ease:”bounce.in`**” will bounce on the way in
	- **`ease:”bounce.inOut”`** will bounce on the way in and out
	- Some eases can be configured :
		- **`ease:”back.config(6)”`** will have a stronger overshoot
	- To customize our ease we use a tool made by GSAP called : [Ease Visualizer](https://gsap.com/docs/v3/Eases/?ref=6234) 
- The stagger property allows you to offset the start time of multiple targets in a single tween.

	- In GSAP3 you no longer need the staggerTo(), staggerFrom(), and staggerFromTo() methods of GSAP2.

```js
// each image will start 0.2 seconds after the previous one starts.
gsap.to("#freds img", {y:-100, stagger:0.2});
```

- A stagger object gives you greater control over where the staggers start from and how the timing is dispersed.

```js
gsap.to("#freds img", {y:-50, stagger:{
  each:0.2,
  from:"end"
  }
});
```

- **each:0.2** means there will be 0.2 seconds **between** the start of each animation. 
- If instead you use **amount:0.2** then all animations will start **within** 0.2 seconds.
### to(), from() and fromTo()
- `to()` animates to the properties you set
- `from()` animates from the properties you set to the default values
- `fromTo()` allow us to set the starting values and the end values : 
	- `gsap.fromTo("target", {<starting_values>,<ending_values>})`
	- If you set a property in the `starting_values` and not add it's ending version in the `ending_values` it will not change : it stays fixed, but NOT VICE VERSA

### Controlling Tween playback
- So to control a tween we have to reference it by storing it in a variable
- To prevent a tween from playing automatically you can set its **paused** special property to true.
```js
var tween = gsap.to("#fred", {x:600, paused:true});
```
- To play that tween you can later call:
```js
tween.play();
```

- From here you can do something like adding a button and making it so that on click the animation plays
- We have other methods :
```js
tween.pause()
tween.reverse()
tween.restart()
```

### transformOrigin
- It's basically like the Pivot point in Davinci resolve (so the center point where the target will scale on, rotate around and so on) 
- By default DOM elements will scale, spin, and skew around their center point.
- If we want to alter that we have access to the css property transform-origin. 
- Like all hyphenated css properties **transform-origin** becomes **`transformOrigin`** when used in a GSAP tween.
- `transformOrigin` values are set with a pair of `horizontal (x)` and `vertical (y)` values as a single string.
- The values are _commonly_ set in **pixels**, **`percents`**, or using the **css keywords**: left, center, right, top, bottom.
- Syntax :
	- `transformOrigin: " <horizontal> <vertical> "`

## Timelines
- So when you're dealing with multiple elements that are animated you most likely want to have them in a timeline : it basically groups them together which will make animating them for example in order very simple because the Timeline will take care of that for you and so on
- A timeline is created with `gsap.timeline()`
- All tweens in a timeline naturally play one after the other.

- A syntax will look something like this :
```js
gsap.timeline()
  .from("#demo", {autoAlpha:0})
  .from("#title", {opacity:0, scale:0, ease:"back"})
  .from("#freds img", {y:160, stagger:0.1, duration:0.8, ease:"back"})
  .from("#time", {xPercent:100, duration:0.2})
```
