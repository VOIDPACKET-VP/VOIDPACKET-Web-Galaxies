# Note 1
- To make a Drop down menu it's best to use this structure :
  ```
	<form>
		<label for="superpowers">Choose Your Superpower:</label>
		<select id="superpowers">
			<option value="flight">Flight</option>
			<option value="invisibility">Invisibility</option>
			<option value="superStrength">Super Strength</option>
			<option value="telepathy">Telepathy</option>
			<option value="timeTravel">Time Travel</option>
			<option value="wisdom">Wisdom</option>
		</select>
		<button type="submit">Reveal My Superpower</button> // optional of course : do what suits your needs
	  </form>
  ```
  - The things in the `<option>` tags are well the options our drop down menu will include
  - If we want one of the options to be selected by default we add `selected` : `<option value="telepathy" selected>Telepathy</option>`
  - We can make it scrollable (so it won't show everything, which might hide some elements) using : `size="<number_of_el>"` inside the `select` tag : `<select id="superpowers" size="4">`
  - You can add the `multiple` keyword inside the `select` tag to choose multiple options instead of 1
  - If you want to separate the options into groups you can put them inside `optgroup` tags :
```
<optgroup label="physical">
	<option value="flight">Flight</option>
	<option value="invisibility">Invisibility</option>
	<option value="superStrength" selected>Super Strength</option>
</optgroup>

<optgroup label="psychological">
	<option value="telepathy">Telepathy</option>
	<option value="timeTravel">Time Travel</option>
	<option value="wisdom">Wisdom</option>
</optgroup>
```
