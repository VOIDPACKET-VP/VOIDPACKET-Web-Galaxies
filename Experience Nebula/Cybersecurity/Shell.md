# REPL : Read-Eval-Print-Loop
- It's an interactive loop that forms the core of a shell. It follows a repeating cycle:
	1. **Read**: Display a prompt and wait for user input
	2. **Eval**: Parse and execute the command
	3. **Print**: Display the output or error message
	4. **Loop**: Return to step `1` and wait for the next command

- This can be simply achieved with a `while` loop
```c++
bool terminate = true;

while (terminate) {
 std::string command;
 std::cout << "$ ";
 std::cin >> command;
 std::cout << command << ": command not found\n";
}
```

- Which means you'll need an exit plan : this can be achieved by adding an `if else` : if the command is equal to `e.g. exit` 
```cpp
if (commmand == "exit") terminate = false;
else std::cout << command << ": command not found\n";
``` 

# Something about std::cin 
- So our `std::cin` works so far fine, but if we want to take a whole sentence with spaces we have to use : 
```cpp
std::getline(std::cin, string);
```


- We can use this to extract words with a certain pattern from a sentence 
```cpp
// extract the first word
std::istringstream iss(sentence);
std::string firstWord;

iss >> firstWord;
```

# Processes
- In the case where the user wants to run a program we have to work with processes 
- In Windows we do so with `CreateProcess` and in POSIX with do so with `fork()` and one of `exec` family  
- Which means we'll need to add
	- `#include <windows.h>` 
	- `#include <unistd.h>` and `#include <sys/wait.h>` 
- I will also be using `#if #else` blocks instead of `std::process`, That's because :
	- I wanna work with them for the first time, they look complex and cool hhhhh
	- IDK if am using `C++26` : it's required for `std::process` 

> What are those `#if #else` : they are preprocessor directives used for conditional compilation, allowing you to include or exclude specific blocks of code before the actual compilation process begins.
> SYNTAX : `#if #elif #else #endif` you must end this conditional with that `#endif` 

## exec family
- There are 6 members of the exec family, the only difference is what type of arguments they take, all you got to do is add one of these letters to the end of `exec` and voila you got a working `exec` hhhhhhhh
	- **`l` (List):** Arguments are passed as a comma-separated list.
	- **`v` (Vector):** Arguments are passed as an array of strings (like `argv`).
	- **`p` (Path):** Automatically searches your system `PATH` for the program.
	- **`e` (Environment):** Allows you to pass custom environment variables.