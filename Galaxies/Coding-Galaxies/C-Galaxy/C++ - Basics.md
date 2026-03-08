
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
- 