- MINUTE REACHED IN COURSE > 2:34:47 

- This is really not all the basics but some of the "Advanced" basics 

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

int scores[5] = {95, 87, 92, 78, 88};
- _Use when_: Storing multiple values of same type
- Fixed-size collection

### 2. **Pointers**

int *ptr;
char *name = "Alice";
- _Use when_:
    - Dynamic memory allocation
    - Passing by reference
    - Arrays and strings
    - Data structures

### 3. **Structures (`struct`)**

struct Student {
    char name[50];
    int age;
    float gpa;
};
- _Use when_: Grouping different data types together
  
### 4. **Unions (`union`)**

union Data {
    int i;
    float f;
    char str[20];
};
- _Use when_: Storing different data types in same memory location (one at a time)

### 5. **Enumerations (`enum`)**

enum Weekday {MON, TUE, WED, THU, FRI, SAT, SUN};
- _Use when_: Working with named integer constants

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


# *Loops*
## **For loops**







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

# Random
- `\0` is called a *Null Buffer* 

- Sometimes when asking for user input, other inputs might get ignored by our C program because the `input buffer` is full even though we didn't enter anything, to counter that : 
	- If we're using `scanf();` we can just add a space before the `%c` or `%d` etc.
		- `scanf(" %c", &grade);`
	- If we're using `fgets();` we'll have to use a function called `getchar();` before the `fgets();`

- When you have a variable that you don't wanna overwrite it (change it's value later), you can add the `const` key word before the declaration : `const double PI = 3.1415` , it's considered Best practice to make the `const` variables ***Capital letters*** .

- To assign we use =, but to compare we use == 



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
	4. 