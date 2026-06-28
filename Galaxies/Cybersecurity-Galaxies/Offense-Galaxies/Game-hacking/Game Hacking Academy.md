
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

## Breakpoints
- The best way to start reversing a game is to figure out what you want to look at and then find where it is. There are many ways to establish that context, but no matter which one you choose you will always use a ==breakpoint==
- They allow the debugger to pause execution of the game at a specific instruction.

>  You can set breakpoints on any type of memory. This includes memory found using a memory scanner.

> Breakpoints can be set to trigger both non-conditionally and conditionally. When a breakpoint is triggered, it’s also known as popping.
### Memory Breakpoints
- Key insight: breakpoints pause AFTER the instruction that touches the memory, not ON it.
- So here is a ==workflow== based on the gold example we did in that game `Wasnoth` :
	1. Find the memory address of gold (Cheat Engine) 
	2. Set memory breakpoint ON that address 
	3. Trigger the event (recruit a unit) 
	4. Breakpoint pops → we're now inside the function that handles gold subtraction 
	5. We can see exactly how gold is calculated and modified
### Code breakpoints
- Used when no obvious variable to scan for, so what we do is set a breakpoint on a text reference :
	1. Find a text string in the game (error message, log) 
	2. Set breakpoint on where that string is referenced 
	3. Trigger the condition in game 
	4. Step OUT of the function until you reach what called it 
	5. Now you're in the function you actually want to modify
### The `nop` instruction
- It's opcode is `0x90`, stands for no operation. When encountering this instruction, a CPU will do nothing and continue on to the next instruction

> So the trick is instead of changing the value, we remove the instruction 


- The RE workflow for game hacking:
	1. Identify what you want to change
	2. Find the memory value (Cheat Engine scanner)
	3. Set a breakpoint to find the CODE that touches it
	4. Read/understand the assembly around the breakpoint
	5. Modify: change a value, NOP an instruction, 
   or inject your own code (code cave)
> Breakpoints are the bridge between "I found the value" and "I found the code"

## Changing Game Code 
- EXAMPLE :
```
Changing Game Code — Workflow

Goal: Make gold not decrease when recruiting units

Steps:
1. Find gold address in Cheat Engine (memory scanner)
2. Close Cheat Engine, open x64dbg
3. Attach x64dbg to the running game process
   File → Attach → select Wesnoth
4. Navigate to gold address in the Dump section
   Right-click → Go to → Expression → paste address
5. Set hardware breakpoint on that address
   Right-click on value → Breakpoint → Hardware, Write → DWORD
   (triggers when anything WRITES to that memory)
6. Resume game execution (press Play until unpaused)
7. Trigger the event in game (recruit a unit)
8. Breakpoint pops → execution pauses
9. Scroll UP in code window to find the sub instruction
   (breakpoint lands AFTER the write, so scroll up)
10. NOP out the sub instruction
    Right-click → Binary → Fill with NOPs
11. Remove the breakpoint (Breakpoints tab → Remove)
12. Resume game → gold no longer decreases ✅

Key concepts:
- EIP = Extended Instruction Pointer
  tells the CPU where it currently is in execution
  when breakpoint pops, EIP shows current location

- Hardware Write breakpoint = triggers when
  memory at that address is WRITTEN to
  (not read, not executed — specifically written)

- Why 3 NOPs? 
  The sub instruction was 3 bytes long
  NOP is 1 byte (0x90)
  So 3 NOPs replace it to maintain code alignment
  (covered in future lesson)

- Why scroll UP after breakpoint pops?
  Breakpoint lands on the instruction AFTER
  the one that wrote to memory
  The sub modifies a register first,
  then mov writes to memory → that's what triggers it
  So sub is always one instruction above
```

## Reversing Code
- This one is hard so pay attention
- EXAMPLE 
```
Reversing Code — Bubbling Up

Goal: recruit units anywhere on the map
Method: find the context menu handler by bubbling up
        from known code (gold subtraction)

Key concepts:

Bubbling Up:
→ Start at known code deep in the call stack
→ Execute till return → lands on retn instruction  
→ Step over the retn → arrives at calling function
→ Repeat until you reach the function you want
→ Like climbing a ladder from the bottom rung

Call vs Return in assembly:
   call some_address  → jump INTO a function
                        (pushes return address to stack)
   retn               → jump BACK to caller
                        (pops return address from stack)

Step Into vs Step Over:
   Step Into  → follow the call, enter the function
   Step Over  → execute the call but stay at same level
                skip over function internals

Function Pointer Arrays (the big discovery):
→ Games don't always use switch statements
→ Often use arrays of function pointers:
   functions[] = {terrain_desc, recruit, attack...}
   functions[option_selected]()  ← called by offset
→ In assembly this looks like:
   call dword ptr ds:[eax + 0x54]
   call dword ptr ds:[eax + 0x28]
   call dword ptr ds:[eax + 0x68]
   (each offset = different menu action)

The hack:
→ Found recruit = offset 0x54
→ Found terrain description = offset 0x28  
→ Found debug spawn menu = offset 0x68
→ Changed terrain description call to use 0x68
→ Now selecting terrain description opens debug menu
→ Debug menu available everywhere → recruit anywhere ✅

Verification method:
→ NOP the call → test in game → nothing happens
→ Confirms you found the right location
→ Restore selection → undo the NOP
→ Then make your real change
```

## Code Caves
- So far the hacks we did only included changing 1 instruction, but what if we want to replace multiple instructions. That's where a ==Code Cave=== comes in.
- It's a section of the game’s memory that we fill with instructions. Most games will have large sections of unused memory between functions or at the end of the executable. These locations are perfect for creating a code cave in.
- So what you need to know is the following :
```
Code Caves

Problem: what if you want to ADD instructions 
         instead of replacing them?
         (keep original + add new behavior)

Solution: Code Cave
→ Find empty/unused memory in the game
→ Write your new instructions there
→ Redirect original code to your cave
→ Jump back when done

Skeleton (always follow this):
┌─────────────────────────────┐
│ pushad                      │  ← save ALL registers
│ [your new code here]        │  ← new functionality  
│ popad                       │  ← restore ALL registers
│ [original instruction]      │  ← keep original behavior
│ jmp back to game code       │  ← return to normal flow
└─────────────────────────────┘

Why pushad/popad?
→ Your new code might change register values
→ Game's next function might DEPEND on those values
→ Without save/restore → game crashes
→ pushad saves eax,ebx,ecx,edx... to stack
→ popad restores them all

The Wesnoth example:
Original:  0x00CCAF90  call [eax+0x28]  ← terrain description
           ↓ replaced with:
Modified:  0x00CCAF90  jmp 0x00D00000   ← jump to cave

Cave at 0x00D00000:
    pushad
    call [eax+0x68]      ← debug menu (new behavior)
    popad
    call [eax+0x28]      ← terrain description (original)
    jmp 0x00CCAF93       ← back to game, instruction after original

Result: selecting terrain description now
        opens debug menu AND shows terrain description ✅
```

> Key rule: only modify what you need, never leave registers in a different state than you found them

