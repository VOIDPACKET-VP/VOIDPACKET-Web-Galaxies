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

- So our `std::cin` works so far fine, but if we want to take a whole sentence with spaces we have to use : 
```cpp
std::getline(std::cin, string);
```
