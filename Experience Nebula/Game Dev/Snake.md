# Grid
- It's a technique in Game dev, where our characters move according to a grid instead of pixels
- In Raylib it's achieved like this :
```cpp
// We initialize the amount of cells and size of each cell as global variables

int cellSize = 30;
int cellCount = 25;


// Then we set the size of our screen by multiplying them :

InitWindow(cellCount * cellSize, cellCount * cellSize, "VOID Snake");
```

# Characters / Objects
- So when we want to have a thing in the game with specific attributes/properties we use `classes`, in this case we need a `Snake` and a `Food` class

> You always need to think about what my Object needs to have, or what do i need to know about this Object

- For example, the ==Food class== :
	1. We need to know it's x and y positions on the grid
		- `Vector2 position = {5, 6};` 
		- You can access them with : `position.x` and `position.y`
	2. Our class needs to have a `Draw` Method :
```cpp
void Draw() {
// You can use any Raylib shape drawing functions
	DrawRectangle(position.x * cellSize, position.y * cellSize, cellSize, cellSize, darkGreen);
}

// Inside the main function, we create the Food Object :
Food food = Food();

// and inside the game loop, after the BeginDrawing(); >
food.Draw();
```

# Using images/assets instead of shapes
- we'll need to use a constructor.
- Make sure your assets are in the same directory as the .slnx file
- We'll use a Raylib struct called ==Image== which basically takes the image's pixel data :
```cpp
// Inside the constructor
Image image = LoadImage("path/to/image.png");
```
- That image needs to be transformed into a texture :
```cpp
// Inside the Food class
Texture2D texture;
// Still Inside the constructor
texture = LoadTextureFromImage(image);
```
- Now that we have the texture we don't need the image, so let's free up some space :
	- `UnloadImage(image);` inside the constructor

- Anytime we have a ==constructor== we need to have a ==destructor==, and inside this one we'll unload the texture :
```cpp
~Food() {
	UnloadTexture(texture);
}
```
- Then we have to change the Draw function to :
```cpp
DrawTexture(texture, position.x * cellSize, position.y * cellSize, WHITE);
```

> Raylib's DrawTexture function displays images at their original size, whereas DrawTexturePro enables scaling, rotation, and cropping. Key to resizing is setting the destination rectangle to the desired dimensions, usually with a source rectangle covering the entire texture.

```cpp
void Draw() {
	Rectangle source = { 0.0f, 0.0f, static_cast<float>(texture.width), static_cast<float>(texture.height) };
	Rectangle dest = {
		position.x * cellSize,
		position.y * cellSize,
		static_cast<float>(cellSize),
		static_cast<float>(cellSize)  
	};
	Vector2 origin = { 0.0f, 0.0f };
	DrawTexturePro(texture, source, dest, origin, 0.0f, WHITE);
}
```
# Random values generation
- Raylib’s **`GetRandomValue(min, max)`** function simplifies grid randomization by generating uniform, pseudo-random whole numbers that are completely inclusive of both boundaries (e.g., `0` to `27` for 28 cells).
- Because Raylib’s built-in **`Vector2`** struct strictly requires floating-point numbers (`float x`, `float y`), modern C++ utilizes **`static_cast<float>()`** to explicitly and safely convert these generated integer coordinates into decimals at compile-time.

> This specific casting method is preferred in game development over old C-style casting because it eliminates compiler warnings regarding implicit data conversions, ensures type safety by catching errors before the game runs, and makes code significantly easier to search and audit during debugging.


# the deque data type :

- Reached minute : 28:14