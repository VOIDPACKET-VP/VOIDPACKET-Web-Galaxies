
# Basics
## Game Fundamentals
- So games are complex and made up of several parts :
	- Graphics, Sounds, Physics, Game Logic etc.
- Due to each part's complexity most games use external functions called Libraries. For example, to draw images and shapes to a screen, most games use either the DirectX or OpenGL library.

> For some type of hacks, it's important to know what libraries are used. For a wallhack we can modify the graphic library 
> For most hacks we'll be modifying game logic

### Game structure
- Most games have two major functions:
	- ==Setup== : is executed when the game is first started. It is responsible for loading images, sounds, and other large files from the hard-drive and placing them in RAM
	- ==Main Loop== : runs forever until the player quits. It is responsible for handling input, playing sounds, and updating the screen etc.

### Memory
- Games have a lot of large resources which must be loaded from the hard drive in the setup phase. Once loaded they are placed in RAM. And because games are so large, they must constantly load different data from the RAM into registers to operate on. This loading is typically done by a **mov** command.

> "Pointers are critical in game hacking: most game values aren't at a fixed address. Instead a base pointer + offsets lead to the value. This is why Cheat Engine has pointer scanning."

## Hacking Fundamentals
- Hacking a game consists of modifying memory in that game which involves these 4 main steps :
	1. ==Identify== what you want to change.
	2. ==Understand== what memory you need to locate.
	3. ==Locate== that memory in the game.
	4. ==Change== that memory

### Identify
- First thing you need to do to hack is identify what you want to do : what do you want to hack
	- Modifying player's money require a memory modification of a variable
	- Wallhack requires memory modification of the game's code

### Understand
- Before we do locate the memory, we need to understand what memory we need to locate, there are 3 main types of modifications :
	1. Variables => modifying a value
	2. Code => modifying logic
	3. Files => modifying saved items for example

### Locate 
- Now that we understand where to look, we can start looking, this can be a ==time consuming process== : For some hacks, this may involve searching memory with a tool called a memory scanner. For others, it may involve looking through the game’s code using a tool called a debugger.

### Change
- Now that you've located that memory, you can modify it, you can make sure it's the right memory by using a memory scanner or debugger initially, then you can write a program to automatically change it for you.

# Debugging & Reversing
- Before we start let's understand a few things :
	- Viewing a game’s code as it is running is known as ==debugging==. Understanding and modifying that code to do what you want is known as ==reversing==.

> You do not have to debug a game to reverse it, but it is very helpful if you can.

## Assembly
- When debugging and reversing a game, we will mainly be dealing with assembly

> Often there are many instructions in a game that are not critical to understand while reversing. Understanding which instructions can be skipped comes with experience.
### Data Management
- Games constantly move data between memory and registers to operate on it. The primary instruction for this is `mov`, which can copy values between registers, load an immediate value, or load a value stored at a specific memory address using `dword ptr ds:[address]`. However, when dealing with objects and classes, games don't always want the value at an address — they want the address itself, so they can navigate to different members inside that object using offsets. This is where `lea` (Load Effective Address) comes in. Instead of loading what's stored at a memory location, `lea` loads the address itself into a register, essentially copying a pointer. Once you have the base address of an object in a register, you can reach any variable inside it by adding an offset — `[eax + 0x04]` for the second member, `[eax + 0x08]` for the third, and so on. This is identical to how pointers and structs work in C++ — `lea` is just C++ pointers at the assembly level.
### Change Data
- Once data is loaded into a register, games will use several instructions to modify the data :
	- `inc` and `dec` => ==increase/decrease== by 1
	- `add` and `sub` 
	- `mul` and `div` => ==multiply/divide== by the value of `eax`
- Some `Bitwise` instructions :
	- `shl` and `shr` => shift ==left/right==
	- `or`, `and` and `xor` 
### Flow control
- Games are made up of hundreds of different functions, to navigate to them from the main loop games use ==Flow control instructions== like :
	- `jmp` => jumps to another section of code to start executing:
	- `call` => execute a function

> a `jmp` instruction permanently changes where a game is executing whereas a `call` instruction temporarily changes it.

- Games will also need to compare values to do something for example if a player reaches 0 lives we show `Game Over` we do that using the following instructions :
	- `cmp` and `test`
```assembly
cmp eax, 2
test eax, eax // this will simply compare it to the value 0
```
- Then we can combine them with `jump` operations to execute parts of code if the comparison meets a condition :
	- `jz` => JUMP IF ZERO
	- `jnz` => JUMP IF NOT ZERO
	- `je` => JUMP IF EQUAL
	- `jne` => JUMP IF NOT EQUAL

### The Stack
- Programs can store information in a place known as the stack, we store it using the `push` and we receive it from the stack using the `pop` 
```assembly
push 5   // push the value 5 to the stack
pop eax  // pop the value into eax
```

- Functions can take params, in assembly we achieve that using the stack, we push the param values and then call the function
```assembly
push 5
push eax
call 0x123456789
```

- Most function calls will start and end with these instructions :
```assembly
push ebp
mov ebp, esp
sub esp, ....

....

leave
ret
```
- The first three are called the ==function prologue== and they set up the stack frame for the function.
- The last two instructions restore the previous function’s stack frame and return to the function that called this current function.