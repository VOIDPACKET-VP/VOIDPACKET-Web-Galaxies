# **Game Structure**
- It can be divided into two parts :

| *Definitions*             | *Game loop*                              |
| ------------------------- | ---------------------------------------- |
| The variables             | Checking for user input                  |
| Creating the game objects | Update the positions of the game objects |
| Creating the Game Window  | Checking for collisions                  |
|                           | Drawing the game Objects                 |
- This is something that all games share
# **The Basic Code**
- The first thing we do is `#include <raylib.h>`
- We create a window using : `InitWindow()` :
	- We tell it the width and height in pixels and name
	- `InitWindow(800, 800, "First Raylib Game");`
- As soon as we do that, we have to add the `CloseWindow();` which should be the last line in our code before the `return 0;`
```
#include <raylib.h>
int main(){
    InitWindow(800, 800, "First Raylib Game");

    // everything else goes here (Game Loop)

    CloseWindow();
    return 0;
}
```
- Now we implement the Game Loop, which will take care of these (as i already said) :
	1. Event Handling
	2. Updating Positions
	3. Drawing Objects
- The game loop is started with :
```
while(WindowsShouldClose() == false){
	1. Event Handling
	2. Updating Positions
	3. Drawing Objects
}
```
- Then we add the drawing function (3rd section in the game loop) :
	- `BeginDrawing();` and `EndDrawing();`
- Now *BEFORE the while Loop* we have to set how fast our game should run :
	- `SetTargetFPS(60);` 
# **The Drawing**
- Now to draw anything in the Window, we use Coordinates : The one used in `Computer Graphics` not in high school :
	- Because the `Origin (0,0)` now is the `TOP LEFT Corner of the screen` not the `Middle` 
	- The `X` coordinates increases as we move `Right`, but the `Y` increases as we move `Down`
- The drawing code is inserted between those two main drawing functions : like a sandwich :
```
BeginDrawing();

// Code goes here

EndDrawing();
```
- To draw a circle we can use the built in raylib function :
	- `DrawCircle(x, y, radius, color);`
	- If we want to put it in the center of our `800x800` window with the color WHITE :
		- `DrawCircle(400, 400, 20, WHITE);`
		- Colors are in Capital letters
# **The MVT**
- For movement, our code goes in the 2nd section : `2. Updating positions` 
- So we can do something like this to move our ball every time the loop runs :
```
#include <raylib.h>
int main(){
    InitWindow(800, 800, "First Raylib Game");
    SetTargetFPS(60);

    int ballX = 400;
    int ballY = 400;

    while(WindowShouldClose() == false){
        // 1. Event Handling

        // 2. Updating Positions
        ballX += 3;

        // 3. Drawing
        BeginDrawing();
        DrawCircle(ballX, ballY, 20, WHITE);
        EndDrawing();
    }

    CloseWindow();
    return 0;
}
```
- But if we do this the ball will leave a trace or a path, to see the ball really move we add after the `BeginDrawing();` this : `ClearBackground(BLACK);`
```
BeginDrawing();
ClearBackground(BLACK);
DrawCircle(ballX, ballY, 20, WHITE);
EndDrawing();
```
- To choose what color we use the Built in `COLOR struct` :
	- `Color <name> = {red, green, blue, alpha}` : similar to CSS
```
Color voidpacket = {154,157,12,200};

while(WindowShouldClose() == false){
        
        ...........

        // 3. Drawing
        BeginDrawing();
        
        ClearBackground(voidpacket);
        
        DrawCircle(ballX, ballY, 20, WHITE);
        EndDrawing();
    }
```
- We can use `Keyboard Controls` to manually change the position of the object :
	- `if(IsKeyDown(KEY_RIGHT)){ballX += 3;}`
	- And we do the same thing for `Left, Up and Down` : but for LEFT and UP we decrease not increase (remember those coordinates)
