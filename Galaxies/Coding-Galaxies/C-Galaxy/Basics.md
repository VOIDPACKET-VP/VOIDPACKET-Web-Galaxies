
# Data Types
## *Primitive (Basic) Data Types*
### 1. **Integer Types**

- **`int`**: Basic integer type
    int age = 25;
    - _Use when_: Working with whole numbers (positive, negative, or zero)
    - Size: Typically 4 bytes (platform dependent)
    - Range: Usually -2,147,483,648 to 2,147,483,647

- **`short`**: Short integer
    short temperature = -10;
    - _Use when_: Memory is limited and you know values will be small
    - Size: Typically 2 bytes
    - Range: -32,768 to 32,767

- **`long`**: Long integer
    long population = 7800000000L;
    - _Use when_: You need larger range than `int`
    - Size: Typically 4 or 8 bytes
    - Range: At least -2,147,483,647 to 2,147,483,647

- **`long long`**: Very long integer (C99+)
    long long bigNumber = 9223372036854775807LL;
    - _Use when_: You need extremely large integers
    - Size: Typically 8 bytes


### 2. **Character Type**

- **`char`**: Single character/byte
    char grade = 'A';
    char byte = 127;
    - _Use when_: Working with single characters or small integers
    - Size: 1 byte
    - Range: -128 to 127 or 0 to 255 (signed/unsigned)

### 3. **Floating-Point Types**

- **`float`**: Single-precision floating point
    float pi = 3.14159f;
    - _Use when_: Working with decimal numbers where precision isn't critical
    - Size: 4 bytes
    - Precision: ~6-7 decimal digits

- **`double`**: Double-precision floating point
    double precisePi = 3.141592653589793;
    - _Use when_: You need more precision than `float`
    - Size: 8 bytes
    - Precision: ~15 decimal digits

- **`long double`**: Extended-precision floating point
    long double veryPrecise = 3.14159265358979323846L;
    - _Use when_: You need maximum precision
    - Size: Platform dependent (often 10, 12, or 16 bytes)

### 4. **Void Type**

- **`void`**: "No type"
    void functionThatReturnsNothing();
    void *genericPointer;
    - _Use when_:
        - Functions return nothing
        - Generic pointers (pointing to any data type)
        - Empty function parameters

## *Type Modifiers*

### 1.**Signed/Unsigned**

- **`signed`**: Can hold positive and negative values (default for most types)
    signed int negative = -5;

- **`unsigned`**: Can hold only positive values (extends positive range)
    unsigned int age = 25;  // Can't be negative
    - _Use unsigned when_: You know values will never be negative
    - Doubles positive range (e.g., `unsigned char`: 0-255 vs `signed char`: -128-127)

## *Derived Types*

### 1. **Arrays**

`int scores[5] = {95, 87, 92, 78, 88};`
- _Use when_: Storing multiple values of same type
- Fixed-size collection
- NOTE : a string is an array 
- To get the size of we'll use the `sizeof()` : `int sizeOfArray = sizeof(array) / sizeof(array[0]);` 
#### *2D Array*
- It's an array where each element is an array : `array[][ <number of columns> ] = {{}, {}, {}};` 
- They are great if you want a matrix or grid of data 
- For strings we must use `2d array` since each string is an array
#### *Array of structs*
- It's an array where each element contains a struct {} 
- Helps organize and groups together related data
- Syntax : `struct Student students[] = {{}, {}, {}};`
- To access the items we will use `indexes` 


### 2. **Pointers**

`int *ptr;`
`char *name = "Alice";`
- The format specifier for pointers is : `%p` 
- It's a variable that stores the memory address of another variable
- They help avoid wasting memory by allowing us to pass the address of a large data structure instead of copying the entire data
- _Use when_:
    - Dynamic memory allocation
    - Passing by reference
    - Arrays and strings
    - Data structures
- e.g. : `int age = 20; int *pAge = &age;` > It's good practice to name a pointer with `p<name of the variable we want it's memory address>`
- These are the same : `int *pAge` and `int* pAge` 
- When passing variables to a function, we are actually passing a copy of that function, with pointers we can pass the `reference` of that variable and then dereference it inside that function : `void birthday(int *age){ (*age)++; }`
- So we dereference with : `(*<pointer_name>)` 
- NOTE : we can also just pass the memory address to a function instead of a pointer (since they are the same)


### 3. **Structures (`struct`)**

`struct Student {`
    `char name[50];`
    `int age;`
    `float gpa;`
`};`
- It's a custom container that holds multiple pieces of related information (similar to Objects in other languages)
- _Use when_: Grouping different data types together
- Now to assign those variable to a value : `struct Student student1 = {"VOIDPACKET", 20, 3.14};`
- To access one of those elements we'll use : `student1.<variable>` > `e.g. student1.name` 
  
### 4. **Unions (`union`)**

`union Data {`
    `int i;`
    `float f;`
    `char str[20];`
`};`
- _Use when_: Storing different data types in same memory location (one at a time)

### 5. **Enumerations (`enum`)**

`enum Weekday {MON, TUE, WED, THU, FRI, SAT, SUN};`
- _Use when_: Working with named integer constants
- Benefit is to replace numbers with readable names
- Constants should all be uppercase letters
- So now we can make variables and set them equal to something from that `enum Weekday` : `enum Weekday today = MON` now if we print `today` we will get `0` , that is the whole purpose of `enum` 

## *Type Qualifiers*

- **`const`**: Read-only variable
    const float PI = 3.14159;
    - _Use when_: Value shouldn't change

- **`volatile`**: May change unexpectedly
    volatile int hardwareRegister;
    - _Use when_: Variable can be changed by hardware/interrupts

## ***Quick Reference Table***

|Type|Typical Size|Use Case|
|---|---|---|
|`char`|1 byte|Characters, small integers|
|`int`|4 bytes|General-purpose integers|
|`float`|4 bytes|Approximate decimal numbers|
|`double`|8 bytes|Precise decimal numbers|
|`void`|N/A|No type, generic pointers|



# *Conditional statements*
## **If else**
- The syntax is pretty straight forward : 
	`if (first condition){`
	`} else if (second condition){`
	`} else {`
	`}`
- You can add as many `else if` statements as you like
## **switch**
- It's an alternative to using many if-else statements
- More efficient when working with fixed integer values
- The syntax is the following :
	- `switch(dayOfWeek) { case 1: printf("it's Monday");break;}`
	- Now here what happens is if `dayOfWeek` is equal to `1` (The first case) it will print `It's Monday` , the `break` breaks out of the `switch` once the condition is matched
	- You can add as many `cases` as you like
	- You can also add a `default` case that will execute if non of the `cases` were matched : It has similar syntax > we replace `case 1:` with `default:` . 

## **Logical operators**
- In C we have :
	1. `AND = &&`
	2. `OR = ||`
	3. `NOT = !`

## **Ternary Operator**
- Syntax : `(condition) ? value_if_true : value_if_false;`



# *Functions*
- They are a reusable section of code that can be invoked, they can take arguments so that they can be used.
## **Syntax**
- We start with the return type (e.g. `void` ), then we give it a name (something descriptive) :
	- `void <function's name>(){}`
- Then to call it we basically type it's name followed by `()` : `<function's name>();`
## **Arguments**
- To pass `arguments` to a function, when we create it we have to add the data types and name of the arguments inside the `()` , here they are called `parameters` : 
	- `void <function's name>(char <name>[], int <name>){}`
- Then when we call the function we have to pass them inside again the `()` 

## **return**
- Returns a value back to where you call a function
- when returning a value, we have to match the value's data type with the function's return type, so :
	- if we're returning an `int` > `int <function's name>(){}`
	- etc.

## **function prototype**
- Provide the compiler with info about a function's : name, return type, params before it's actual definition
- It's considered best practice to use them : they improve readability, organization and helps prevent errors 
- e.g. :
	- `void <function's name>(char <name>[], int <name>);` 



# *Loops*
## **For loops**
- Syntax : `for(Initialization; condition; update){ <code goes here> }` 
- e.g. : `for (int i = 0; i < 10 ; i++){ printf("i is equal to %d\n", i); }`
## **While loops**
- Syntax : `while(condition){ <code goes here> }`
### *Do While loop*
- It's similar to a normal `while` loop, the only difference is it executes a piece of code and only then it checks the condition, but in a normal while loop we don't execute the code until the condition is satisfied 
- Syntax : `do{ <code goes here> }while(condition);`

## **Break and Continue**
- `break;` is to break out of a LOOP > ***STOP***
- `continue;` is to skip the current cycle of a loop > ***SKIP*** 

# Libraries
## *<string.h>*
- It's a library that gives us a lot of functions related to working with strings :
	- `strlen(<string_variable>)` > gives us the length of a string

## *<math.h>*
- It's a library that gives us a lot of *Math* functions :
	- `sqrt()` > The square root
	- `pow(base, power)` > Rase a base to a given power
	- `round()` > Rounds a number
	- `ceil()` > Rounds up a number
	- `floor()` > Rounds down a number
	- `abs()` > The absolute value
	- `log()` > The logarithmic function 
	- `sin(), cos(), tan() ...` > Trigonometry functions

## *<stdbool.h>*
- It's a library that gives us the possibility to work with Booleans : `True and False` 
- We declare Boolean variables like this : `bool isTrue = true;` 

## <windows.h> && <unistd.h>
- These contain sleep function, the `windows.h` is for windows machines, and `unistd.h` is for Linux and Mac machines
- In windows : `Sleep( <duration in ms> );`
- In Linux/Mac : `sleep( <duration in s> );`

# *Memory*
## **malloc()**
- It's a function that dynamically allocates a specified number of bytes in memory 
- e.g. `char *pGrades = malloc( <size in bytes> );` 
- Then we will need to ***return back that memory space*** since we just "borrowed it" : `free(pGrades);` 
- Then we will have to give the ***KEY*** back, which is the `pointer` : `pGrades = NULL;` 
- If the `malloc()` fails it will return `NULL` which can cause `Segmentation Fault` so we need to check for that using an `if` statement, so if it fails we should `return 1;` to exit the program

## **calloc()**
- Similar to `malloc()` but it sets all allocated bytes to 0
- `malloc()` is faster, but `calloc()` leads to less bugs
- we will have to import `<stdlib.h>` 
- Syntax : `calloc(<number of elements>, <size of element>);`
- Then don't forget to `free()` the memory and return the key 

## **realloc()**
- resize the previously allocated memory 
- we will have to include : `<stdlib.h>`
- Syntax : `realloc(<pointer>, bytes);`
- The `realloc()` will return a pointer to some new memory and copy the values from the old memory `<pointer> that's inside the realloc()` and will also `free()` the old memory
- Now again if it fails it will return  a `NULL` so we have to check for that


# *Random*
- `\0` is called a *Null Buffer* 

- Sometimes when asking for user input, other inputs might get ignored by our C program because the `input buffer` is full even though we didn't enter anything, to counter that : 
	- If we're using `scanf();` we can just add a space before the `%c` or `%d` etc.
		- `scanf(" %c", &grade);`
	- If we're using `fgets();` we'll have to use a function called `getchar();` before the `fgets();`

- When you have a variable that you don't wanna overwrite it (change it's value later), you can add the `const` key word before the declaration : `const double PI = 3.1415` , it's considered Best practice to make the `const` variables ***Capital letters*** .

- To assign we use =, but to compare we use == 

## **Pseudo-random**
- we can generate stuff that appear to be random but are determined by a mathematical formula that uses a seed value to generate a predictable sequence
- Advanced techniques : `Mersenne Twister` or `/dev/random` ...
- We will need the `#include<stdlib.h> and <time.h>`, this way we can create a seed based on time 
- Syntax : `srand(time( <use NULL or 0> ));` then to access the random number we call the `rand()` function

## **typedef**
- It allows us to give a `nickname` to existing `data types`, > `e.g. int becomes numbers`
- Syntax : `typedef <data type> <new name>` > `typedef int numbers` 
- so now instead of using `int` when declaring an `int variable` we will use `numbers`

## **Work with files** 
- We have a built in `struct FILE` inside the `<stdio.h>`, the data type is : `FILE` 
- To create a file we use : `fopen("<path>", "<mode e.g. w to write, r to read>");` > e.g. `FILE *pFile = fopen("name.txt", "w");`
- To write to a file : `fprintf(<file e.g. pFile>, "<format specifier>", <what to write>)`
- To read a file : 
	- we will need to use `read mode : r` in `fopen()` 
	- Then we will need a `buffer` where data will be stored temporarily for us to read : `char buffer[ <size in bytes e.g. 1024> ] = {0};` 
	- Then we will use : `while ( fgets(buffer, sizeof(buffer)), pFile) != NULL) { printf("%s", buffer); }`
- To close the file : `fclose(pFile);` > *VERY IMPORTANT TO ALWAYS CLOSE THE FILE* 
- Now if the `fopen()` fails we should exit the program by : `return 1;` 

# Project Ideas

- The projects are organized from ***Beginner*** to ***Advanced*** :
	1. `Shopping Cart Program` : User chooses an item, sets a price and amount, the program returns the Total amount.
		- You can take it further by allowing the user to choose multiple items
		- You set the price
		- etc.
	2. `Area of a circle` : Given a radius, the program should calculate the Area of the circle.
		- You can expand the scope from circles to cylinders, rectangles etc.
	3. `Weight converter program` : The user chooses a choice : kg to pounds or the opposite, then the program gives the converted value
		- You can add other units : temperature, speed, volume etc.
