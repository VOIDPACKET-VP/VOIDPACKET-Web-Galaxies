
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

```
// Game dev example
enum State {
    IDLE = 0, RUNNING = 5, JUMPING // JUMPING will automatically become 6
};
```
# **Constructors**
- It's a special method that runs when we create a new instance of a class
- It's a class method that allows us to initialize variable to `0`, so instead of letting them take what was left from memory when we allocate memory for them, they get set to 0
- It's name *must be exactly the name of the class*
- The primary use of it is to initialize that class and memory for it
```
class Entity {
public:
	float x, y;
	
	Entity() { // constructor
		x = 0.0f;
		y = 0.0f;
	}
	
	void Print(){
		std::cout << x << "," << y << std::endl; 
	}
};

int main(){
	Entity e;
	e.Print();
}
```
- You can have as many constructors you want, they all must have the same name (It's not an issue), and you can add parameters to those constructors
```
class Entity {
public:
	float x, y;
	
	Entity() { // constructor
		x = 0.0f;
		y = 0.0f;
	}
	
	Entity(float X, float Y){
		x = X;
		y = Y;
	}
	
	void Print(){
		std::cout << x << "," << y << std::endl; 
	}
};

int main(){
	Entity e(10.2, 11.47);
	e.Print();
}
```
- By default C++ applies a default constructor for us, and we can tell the compiler 'no we don't want that constructor' by :
  ```
  <constructor_name>() = delete;
  // There are other types of constructors like the move and the copy
  ```
# **Destructors**
- It runs when we destroy an Object
- `constructor` for initialization : to set up things for us, and `destructor` is for termination : it cleans everything that we used 
- It applies for stack and heap objects
- The only difference in syntax is we add `~` in front of the name : `~Entity(){}` 
- If we don't use them we can risk `memory leaks` 
- Destructors are mostly used when you used `new` in your constructor. If you manually allocated memory on the Heap (`new`), the destructor is where you _must_ call `delete`.
# **Inheritance**
- It's one of the most powerful features of OOP
- It allows us to have a hierarchy of classes which relate to each other : so we can have a base class which have common functionality, and allow us to branch from it and create sub-classes
- It helps so much with code duplication, remember we have to keep our code DRY
- The syntax is pretty straight forward :
```
class <sub-class-name> : public <base-class> {
};
```

```
// Game example
class Entity {
public:
	float X, Y;
	void Move(float xa, float xy){
		X += xa;
		Y += ya;
	}
};

class Player : public Entity { 
	const char* Name; 
};

int main(){
	std::cin.get();
}
```
- here the `Player class` is not only of `type Player` but also of `type Entity` : so both
- Now our sub-class contains everything that our base class has
# **Virtual Functions**
- They allow us to overwrite methods in sub-classes :
	- Let's say we have 2 classes : A and B, B is a sub-class of A
	- If we have a method in A and we marked it as virtual, we can overwrite it in the B class
- The syntax : we add the key word `virtual` in front of the method or function in the main class, and in the sub-class where we overwritten it we mark it with the keyword `override` as best practice
- They are not free of course : it adds two run times 
- **Why we need it:** Imagine you have a `Shoot()` function. A normal gun shoots one bullet, but a Shotgun shoots five. You want to overwrite the normal `Shoot()` for the Shotgun
```
class Weapon {
public:
    int ammo = 30;
    // We add 'virtual' so sub-classes know they are allowed to change this
    virtual void Shoot() {
        ammo--;
        std::cout << "Pew! 1 bullet fired." << std::endl;
    }
};

class Shotgun : public Weapon {
public:
    // We use 'override' just to be safe and clear
    void Shoot() override {
        ammo -= 5;
        std::cout << "BOOM! 5 bullets fired." << std::endl;
    }
};

int main() {
    Weapon m4;
    m4.Shoot(); // Prints: Pew! 1 bullet fired.

    Shotgun doomStick;
    doomStick.Shoot(); // Prints: BOOM! 5 bullets fired.
}
```
# **Pure Virtual Functions : aka Interface**
- It allows us to define a function in a base class that doesn't have an implementation and force sub-classes to implement that function :
	- So these functions don't have code inside them pretty much, they don't do much, and we force every sub-class to have it's own version of that function
	- So if the sub-class doesn't implement that function, we can't instantiate the sub-class
- **Why we need it:** You want to make an `Interactable` class for your 2D game. You want Doors to open, and Chests to give loot when the player presses 'E'. You _force_ every interactable object to have an `Interact()` method, but the base class doesn't do anything itself :
```
class Interactable {
public:
    // The "= 0" means: "This is pure. I won't write code here. 
    // Any class that inherits me MUST write their own Interact() code."
    virtual void Interact() = 0; 
};

class Chest : public Interactable {
public:
    void Interact() override {
        std::cout << "Chest opened! You got 50 gold." << std::endl;
    }
};

class Door : public Interactable {
public:
    void Interact() override {
        std::cout << "Door unlocked. Loading next level..." << std::endl;
    }
};
// If you tried to make a class without Interact(), the compiler would give you an error!
```
# **Visibility**
- It refers to how visible a member or method of a class actually are : so who can call, see and use them
- We have 3 options in C++ :
	- private `(the default option in classes)` : *only the main class*
	- protected : *only the main class and it's subclasses*
	- public `(the default option in structs)` : *everyone*
- Visibility is not something that really has a use case, it's all about work style. But in Game Dev, it has a _massive_ use case called **Encapsulation** :
	- Use case: It protects you from yourself. If `Player.health` is public, any random enemy script can accidentally do `player.health = 5000;`. If it's private, they have to use `player.TakeDamage(10);`, which allows you to run death animations or play sounds safely.
# **Arrays**
- Syntax is similar to C : `<data_type> <name>[size];` > `int array[5];`
- **Arrays are just Pointers**
	- An array `int arr[5]` is basically just a pointer to the first element.
- **The Math:**
	- When we do `arr[2]`, C++ is secretly doing: `*(arr + 2)`.
	- It knows an `int` is 4 bytes, so it jumps $2 \times 4 = 8$ bytes ahead automatically.
- **The Hack (Pointer Arithmetic):**
	- If we turn the pointer into a `char*` (1 byte), we have to do the math ourselves.
		- `*((char*)ptr + 8)` is the same as `ptr[2]`.
	- If I move by bytes (using `char*`), I have to cast back to `(int*)` before I dereference. Otherwise, the compiler gets confused about how many bytes I'm trying to write. It's like: **Move as a char -> Write as an int.**
		- `*((int*)((char*)ptr + 8) ) = 6;` 
```
int array[5]; // created on the stack (will be destroyed as soon as our function ends)
int* another_arr = new int[5]; // created in the heap (we will have to destroy it ourselves or until the program ends)
// we can delete it using the delete keyword, and since it's an array we have to add [] <name_of_array>
delete[] another_arr;
```
- **Why `delete[]` and not just `delete`?** 
	- When we use `new int[5]`, the compiler stores the size of the array somewhere hidden. When we call `delete[]`, the brackets tell C++: "Go look for that hidden size and call the destructor for **every single item** in this array." If we forgot the `[]`, it might only delete the first element, leaving the rest as a **Memory Leak**.
- So we create it on the `Heap` when it has to do with lifetime :
	- For example we have a function that returns an array, well here we need to create the array using the `new` keyword
- In C++ 11 we have a new version of arrays that allow us to know the size of the array, bounce checking etc.  :
  ```
  #include <array>
  std::array<<type>, <size>> <name>;
  we can access the size with : <name>.size(); 
  ```
- But most game developers still use raw arrays in high-performance code to keep things as fast as possible.
# **Strings**
- In C++ : the standard library has a class called : `std::string` which is what we'll be using to work with strings.
- But we still can work with strings the same way as C
- Strings are just an array of characters, when we declare a string we are actually declaring it as a pointer : because remember a string is an array and arrays are pointers
- We also have to include the string library if we want to print it out, otherwise the standard library has a definition of it : `#include <string>`
- So how does it work :
	- `std::string name = "voidpacket";` that's it
	- We do have methods :
		- `name.size();`
		- `name.find();`
			- `bool contains = name.find("void") != std::string::npos;`
	- If we want to append strings, we can't do it the same way as a high level language (e.g. JS) : `std::string name = "void" + "packet";` //this is wrong, because when we declare a sting this way in reality it's a `const char` which means it can't be modified (same as in JS)
		- What we do is :
			- `std::string name = "void";` then `name += "packet";`
			- Or `std::string name = std::string("void") + "packet";`
***NOTE*** :
- If we want to pass a string to a function we don't do : 
```
void printString(std::string string){}
// cause here we are making a copy of that string which will not modify the original one, plus copying a sting will slow our program
// So what we do is we pass it as CONST REFRENCE (the const is optionel)
void printString(const std::string& string){}  
```
- Also string literals are the ones we put inside : `""` , but characters inside : `''` 
- Strings always end with a Null terminator : `\0` 
- If we want to overwrite a char in our string this is how we should declare our string :
  ```
  char name[] = "void";
  name[2] = 'y';
  
  and not like this :
  char* name = "void"; // this is because we are trying to overwrite something that's stored in a READ ONLY space in memory
  Also if we want to declare it with a * it's better to add the const :
  const char* name = "void"; 
  // But REMEMBER string literals are always stored in READ ONLY memory
  ```
- We know that `char` is 1 byte, but there are other types :
	- `wchar_t` : `const wchar_t* name = L"void"; // don't forget to add that L`
		- Which takes 2 bytes
	- `char16_t` : `const char16_t* name = u"void"; // don't forget to add that u`
		- Which takes 2 bytes, made for `utf-16`
	- `char32_t` : `const char32_t* name = U"void"; // don't forget to add that U`
		- Which takes 4 bytes, made for `utf-32`
- There is this library, that has some functions to make our lives easier :
```
#include <string>

int main(){
	using namespace std::string_literals;
	// now we can do stuff like append strings much easier
	
	std::string name = "void"s + "packet"; // see that s

}
```
- if we wanna work with those other string data types this is how :
  ```
  // wchar_t :
  std::wstring name = L"void"s + L"packet";
  // char16_t :
  std::u16string name = u"void"s + u"packet";
  // char32_t :
  std::u32string name = U"void"s + U"packet";
  ```
  - If we want to have multiple lines in our string : we add an `R` at the beginning of it :
	  - `const char* para = R"(text_goes_here)";`
- For more check : [cplusplus](https://cplusplus.com/reference/string/string/)
# **Const**
- It's a keyword we use to promise that our variable will always be constant
- We can break that promise hhhhhhhh and bypass it just in real life (don't do that, Be a man of Honor)
- Breaking the promise :
  ```
  const int MAX_AGE = 90;
  const int* a = new int; // this is similar to this : int const* a = new int
  *a = 2; // THIS WILL GIVE US AN ERROR
  a = (int*)&MAX_AGE; // THIS WON'T GIVE US AN ERROR
  
  // so when we declare the const then int* we can make the pointer point somewhere else, but not change it's content
  
  AND the exacte opposite happense if we declare int* then const :
  
  const int MAX_AGE = 90;
  int* const a = new int;  
  *a = 2; // THIS WON'T GIVE US AN ERROR
  a = (int*)&MAX_AGE; // THIS WILL GIVE US AN ERROR 
  
  And we can do this :
  
  const int* const a = new int
  
  which means we can't change the value or make it pointe somewhere else
  ```
-  The `const` Keyword in Classes (The "Read-Only" Promise)
	- When you put `const` at the _end_ of a class method, you are making a promise to the compiler: **"This function will strictly read data. It will absolutely NOT change any variables inside this class."**
	- Here is exactly how it looks in a Game Dev scenario:
```
class Player {
private:
    int health = 100;

public:
    // ❌ NON-CONST: This function modifies the class, so it CANNOT be const.
    void TakeDamage(int damage) {
        health -= damage; 
    }

    // ✅ CONST: This function only reads data. It promises not to touch 'health'.
    int GetHealth() const {
        return health;
    }
    
    // If you tried to do `health = 50;` inside GetHealth(), the compiler would throw an error!
};
```
- Why do we even need this?
	- Look back at the string notes where you wrote: ```
```
void printString(const std::string& string)
```

- I noted that passing by **const reference** is the best way to avoid slow copies. But here is the catch: **When an object is marked as `const`, you are ONLY allowed to call `const` methods on it.**
- Imagine we write a function to display our player's stats on the screen. To make it fast, we pass the Player by const reference:
```
void RenderPlayerStats(const Player& myPlayer) {
    // This works perfectly because GetHealth() promises not to change anything.
    int currentHP = myPlayer.GetHealth(); 
    
    // THIS WILL CRASH THE COMPILER! 
    // myPlayer is const, and TakeDamage is NOT a const method. 
    // The compiler stops you from accidentally breaking your "Man of Honor" promise.
    myPlayer.TakeDamage(10); 
}
```
# **Mutable**
- It's a keyword, mostly used inside classes
- Marking a member variable of a class `mutable` means that we can modify it's value inside `const methods`
- Another use is with `lambdas` (still not reached the video on those yet) 
# **Constructor Member Initializer Lists**
- It's a way for us to initialize `class member functions` in the `constructor`
- So when we write a `class` and we add `members` to that class, we need a way to initialize them, usually done in the `constructor` 
- There are 2 ways :
```
// 1. Usual way

class Entity {
private:
	std::string m_Name;
public:
	Entity(){
		m_Name = "Unknown";
	}
	
	Entity(const std::string& name){
		m_Name = name;
	}
	
	const std::string& GetName() const {return m_Name;}
};

int main(){
	Entity e0;
	std::cout << e0.GetName() << std::endl;
	Entity e1("Void");
	std::cout << e1.GetName() << std::endl;
	std::cin.get();
}
```

```
// 2. The C++ way

class Entity {
private:
	std::string m_Name;
	int m_Score;
public:
	Entity() : m_Name("Unknown"), m_Score(0){ // Here is our initializer list
	}
	
	Entity(const std::string& name) : m_Name(name){
	}
	
	const std::string& GetName() const {return m_Name;}
};

int main(){
	Entity e0;
	std::cout << e0.GetName() << std::endl;
	Entity e1("Void");
	std::cout << e1.GetName() << std::endl;
	std::cin.get();
}
```
- In that list we have to initialize our members in the same order we have declared them as members
- So why would we use it :  cause it doesn't look like we did much, 2 reasons :
	1. Coding style, this is way cleaner : you can initialize the variables on top and the rest of code inside those `{}` 
	2. ***MOST IMPORTANTLY*** : if we don't do it this way the `member variable` will be `constructed twice` : 
```
class Entity {
private:
	std::string m_Name; // the first time
public:
	Entity(){
		m_Name = "Unknown"; // the second time
		// because this is similar to this : m_Name = std::string("Unkown");
	}
```
# **Ternary Operators**
- Similar to JS : `condition ? if true : if false;`
# **How to create Objects**
- So when we create a class and it's time to use it, we have to instantiate it, we have 2 choices and the difference between them is : `Which memory we'll be creating our object in ?` SO `THE STACK and THE HEAP` 
- 