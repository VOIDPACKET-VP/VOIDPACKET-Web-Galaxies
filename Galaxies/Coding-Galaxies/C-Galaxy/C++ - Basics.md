
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