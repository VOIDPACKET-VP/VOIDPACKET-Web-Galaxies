
### So far everything seems like C

# **Pointers**
- It's an integer (number) that stores a `memory address`  (no matter what data type), that address is what tells us where that specific byte is located in memory.
```
int var = 8;
void* ptr = &var;
// ptr will hold the address of var
// pointers gives us the power to access the value of var using derefrencing
*ptr = 10; // similar to var = 10;
```
- Same thing for `pointer to pointer` : since a pointer is also a variable, it's also stored somewhere in memory, and with `pointer to pointer` we are storing the address of pointer that holds the address of the variable :
```
int** second_ptr = &ptr;
```
# **References**
- They are not your typical variable : they don't take space in memory, and they are similar to a pointer.
```
int a = 5;
int& ref = a;

// more complex scenario : Using Refrences
void Increment(int& value){
	value++;
}
int main(){
	int a = 5;
	Increment(a);
}
 
 // Using Pointers
 void Increment(int* value){
	(*value)++;
}
int main(){
	int a = 5;
	Increment(&a);
}
```
# **Classes**
- It's a way to group data and/or functionality together
```
// Syntax : remember that class is new type of data
class <name> {
};

// exemple : Player in a game >
class Player {
public:   // this allows us to access these variables (x, y and speed) from anywhere
	int x, y;
	int speed;
};

int main(){
	Player player;
	player.x = 0; // this is how we access those variables
}
// variables that are made from class types are called Objects, and a new object variable is called an Instance

// exemple : Moving the player >
class Player {
public:   
	int x, y;
	int speed;
};

void Move(Player& player, int xa, int ya){ // we have passed it as a refrence because we will be modifying the player object
	player.x += xa * player.speed;
	player.y += ya * player.speed;
}

int main(){
	Player player;
	Move(player, 1, 2);
}
```
- We can move that `Move()` function inside the `class` , and here : functions that are inside classes are called `Methods`
```
// exemple : Moving the player >

class Player {
public:   
	int x, y;
	int speed;
	void Move(int xa, int ya){
		x += xa * speed;
		y += ya * speed;
	}
};

int main(){
	Player player;
	player.Move(1, 2);
}
```
- This is a cleaner way to write code.
# **Struct**
- The difference between `class` and `struct` is almost none :
	- A `class` is private by default
	- A `struct` is public by default
- They have the same syntax, and we can use them for the same things
- So THE CHERNO's way of when to use each of them :
	- `structs` : to handle data
	- `class` : If you'll use `inheritance` and/or you will need a `class` full of functionality . 
# **Static**
- It has 2 meanings : one when used inside a `struct or class` and another when used outside them.
1. ***Static Outside a Class (The "Invisible" Variable)***
	- If you define a variable or a function as `static` at the top of a `.cpp` file (global scope), it means: **"This variable is private to this file only."**
	- **The Problem:** Normally, if you have `int x = 5;` in `FileA.cpp`, and you try to create `int x = 10;` in `FileB.cpp`, the **Linker** will scream at you: _"Multiple Definition Error! I don't know which 'x' to use!"_
	- **The Fix:** If you write `static int x = 5;`, it tells the linker: _"Don't show this 'x' to any other files. Keep it hidden here."_
> **Analogy:** It's like a "Local Global." It’s global to the file, but invisible to the rest of the project.

2. ***Static Inside a Class (The "Shared" Variable)***
	- This is what you'll use constantly in **Godot** or **Game Dev**. If you put `static` inside a Class, it means: **"There is only ONE copy of this variable for the entire Class, no matter how many objects you create."**
	- **Without Static:** If you have a `Player` class and a variable `int score`, every time you do `Player p1; Player p2;`, each player has their own separate score.
	- **With Static:**
```
class Player {
public:
    static int playerCount; // Shared by ALL players
    Player() { playerCount++; }
};
```
- If you create 500 players, there is still only **one** `playerCount` in memory. If `p1` changes it, it changes for `p2` as well.
> **Analogy:** It’s like a "Class-wide Bulletin Board." Everyone in the class can see it and change it, but there’s only one board in the room.

- The "Static Function" Trick : 
	A static function inside a class can be called **without creating an object**.
	- Normal: `Player p1; p1.Jump();`
	- Static: `Player::GetTotalPlayers();` (You don't need a `p1` to exists to call this).

- If you're wondering: _"If it's shared/hidden, where is it stored?"_ Static variables are stored in a special part of the memory (the **Data Segment**), not on the Stack or the Heap. They live for the **entire duration** of the program.
- For `static variables` we can use this naming convention : `s_<name>` 
# **Enums**
- It's a way to give a name to a value, so instead of having `int a, b, c;` we can just have am `enum` that has the variables `a, b and c`
- An `enum` is a `4 byte integer`
- Syntax and example :
  ```
  enum <name> {
	  A, B, C // these are always integers, and they are set to 0 by default
  };
  
  >>
  enum Example {
	  A, B, C
  };
  
  int main(){
	  Example value = B; // if we do something like : Example value = 2; we will get an error, we can only use one of the variables inside the enum Example
  }
  ```
- We can specify what data type (but it has to be an `int`) :
  ```
  enum <name> : <type e.g. char> {
  };
  // a char is an int at the end of the day
  ```
