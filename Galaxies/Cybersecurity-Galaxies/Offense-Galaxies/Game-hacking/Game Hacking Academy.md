
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

### Code cave example :

```
Code Caves — Real Example (Wesnoth Gold Hack)

Goal: set gold to 999 when Terrain Description is selected

════════════════════════════════════════════════

WHAT I NEED BEFORE STARTING
────────────────────────────
Two addresses:
  1. Hook location  → where I redirect the game's code
                      (the instruction I'll replace with a jmp)
  2. Cave location  → where I write my new code
                      (empty memory, usually end of executable)

════════════════════════════════════════════════

STEP 1 — FIND THE CAVE LOCATION
────────────────────────────────
Scroll to the end of the executable module in x64dbg.
At the end of most executables there's a large section
of 0x00 bytes — unused, empty, safe to overwrite.
This is where I put my cave.

════════════════════════════════════════════════

STEP 2 — FIND THE HOOK LOCATION
────────────────────────────────
Find the instruction I want to redirect.
This is the instruction I'll replace with a jmp.

Important: jmp is 5 bytes long.
So I need AT LEAST 5 bytes at the hook location.

If the instruction there is smaller than 5 bytes,
I take the next instruction too until I have >= 5 bytes.
Whatever bytes are left over → fill with NOP (x64dbg does this automatically).

In this example:
  8B01        mov eax, dword ptr ds:[ecx]     → 2 bytes
  8D7426 00   lea esi, dword ptr ds:[esi]     → 4 bytes
  Total = 6 bytes → enough for a 5 byte jmp + 1 NOP

Both instructions get replaced by:
  jmp 0x0134360E   (5 bytes)
  nop              (1 byte — automatic)

And since I replaced two instructions,
I MUST recreate both in my cave.

════════════════════════════════════════════════

STEP 3 — PLAN THE CAVE ON PAPER FIRST
───────────────────────────────────────
CRITICAL RULE: you cannot INSERT instructions in memory.
You can only OVERWRITE.
Think of it like painting over a canvas, not like a text editor.

So before touching x64dbg, I write out the complete
final cave on paper or in a text file:

  pushad
  [new hack code]
  popad
  [original instructions I replaced at hook location]
  jmp back to game code (hook location + number of bytes replaced)

In this example, the complete cave:
  pushad
  mov dword ptr ds:[0x5F3B85C], 0x3E7   ← set gold to 999 (0x3E7)
  popad
  mov eax, dword ptr ds:[ecx]            ← original instruction 1
  lea esi, dword ptr ds:[esi]            ← original instruction 2
  jmp 0xCCAF90                           ← back to game (hook + 6 bytes)

════════════════════════════════════════════════

STEP 4 — PAUSE THE GAME
────────────────────────
Before writing ANYTHING, pause the game in x64dbg.
If the game is running and accidentally enters my
half-written cave → it jumps to incomplete code → crash.
Always pause first, write everything, then resume.

════════════════════════════════════════════════

STEP 5 — WRITE THE CAVE
────────────────────────
Navigate to cave location (0x0134360E).
Write instructions top to bottom, one by one.
Do NOT try to go back and insert between instructions.
Write the complete final version in one pass.

════════════════════════════════════════════════

STEP 6 — WRITE THE JMP AT HOOK LOCATION
─────────────────────────────────────────
Navigate to hook location (0x00CCAF8A).
Replace the first instruction with:
  jmp 0x0134360E
Make sure "Fill with NOPs" is checked in x64dbg.
This handles the leftover byte automatically.

════════════════════════════════════════════════

STEP 7 — VERIFY BEFORE TESTING
────────────────────────────────
Set a breakpoint somewhere inside the cave.
Resume the game.
Trigger the event (select Terrain Description).
If the breakpoint pops → redirection is working ✅
Remove the breakpoint.
Test in game → gold should be 999.

════════════════════════════════════════════════

SKELETON APPROACH vs DIRECT APPROACH
──────────────────────────────────────
Skeleton approach:
  → write minimal cave first (just pushad/popad + originals + jmp back)
  → verify redirection works with a breakpoint
  → THEN overwrite with the complete final cave
  → useful for complex caves where you want to verify step by step

Direct approach:
  → plan complete cave on paper first
  → write the full final cave in one pass
  → simpler and faster for straightforward hacks

Both are valid. Choose based on complexity.

════════════════════════════════════════════════

THE RULE THAT PREVENTS CRASHES
────────────────────────────────
Always use pushad/popad around new code:
  pushad  → saves ALL register values to the stack
  [code]  → my new instructions (can freely use registers here)
  popad   → restores ALL register values from the stack

Why? The game's next function might depend on
register values being exactly what they were.
If I accidentally change eax and the game expects
eax to be a specific value → exception → crash.
pushad/popad = insurance against this.
```

## Dynamic memory allocation
- Theory :
```
Dynamic Memory Allocation (DMA)

════════════════════════════════════════════════

WHY DOES THE ADDRESS CHANGE EVERY RESTART?
────────────────────────────────────────────
Games are too large to fit everything in RAM at once.
So they load resources WHEN NEEDED and unload them when done.
This process = Dynamic Memory Allocation (DMA).

When Wesnoth starts → Player class gets allocated somewhere in RAM
The OS decides WHERE → the game has no control over this
Every restart → OS picks a different location
Result → gold address is different every time

This is why Cheat Engine finds a different address each session.

════════════════════════════════════════════════

THE SOLUTION: BASE POINTER
───────────────────────────
Some addresses MUST be constant — the game needs to 
find its own data somehow.

Example: Wesnoth always knows where the Player class starts.
If I find the Player class address → it's always the same.
From there I use OFFSETS to reach gold:

  Player class address (constant) + offset → gold address

This constant address = BASE POINTER
Base pointer + offsets = always leads me to gold
no matter how many times the game restarts.

This is EXACTLY the pointer chain concept in Cheat Engine.

════════════════════════════════════════════════

3 METHODS TO DEFEAT DMA
────────────────────────

METHOD 1 — Cheat Engine Pointer Scan (easiest)
  → Find gold address in current session
  → Right-click → Pointer Scan
  → Cheat Engine finds all addresses that POINT to gold
  → Restart game, find gold again
  → Compare old scan with new scan
  → Keep only addresses that pointed to gold BOTH times
  → Repeat until left with consistent base pointer + offsets
  → Save this → now works every session ✅

METHOD 2 — Code Cave
  → Find instruction that accesses gold (the sub instruction)
  → Redirect to a code cave immediately after it
  → In the cave, save the gold ADDRESS to a location I control:
    
    pushad
    mov dword ptr ds:[0x12345678], edx+4  ← save gold address
    popad
    [original instruction]
    jmp back

  → Now 0x12345678 always holds the current gold address
  → My hack reads from 0x12345678 → always finds gold ✅

METHOD 3 — Reversing (most powerful, most complex)
  → Find the instruction that touches gold (sub instruction)
  → edx+4 holds the gold address — where does edx come from?
  → Scroll up, find where edx was assigned → maybe from eax+60
  → Where does eax come from? → scroll up again
  → Keep going up the chain until reaching a CONSTANT address
  → That constant = base pointer
  → All the offsets collected along the way = the chain
  → Combine them: base + offset1 + offset2 + ... = gold ✅
  → This is the most reliable method long term

════════════════════════════════════════════════

COMPARISON
───────────────
  Cheat Engine scan  → easy, guided, good for beginners
  Code cave          → medium, saves address dynamically
  Reversing          → hard, most versatile, works forever

In real game hacking:
  → start with Cheat Engine to find the address
  → use reversing to find the base pointer
  → code cave as a middle ground when reversing is too complex

════════════════════════════════════════════════

CONNECTION TO EARLIER CONCEPTS
────────────────────────────────
Remember the LEA lesson?
  lea eax, [ecx]  → load the ADDRESS into eax

That's exactly what's happening here.
The game uses pointers and offsets internally
to navigate its own class structures.
DMA defeating = reading those same pointers
the same way the game does.

When you scan for a pointer chain in Cheat Engine
you're essentially reverse engineering how the game
navigates its own memory — 
the same thing it does with LEA and MOV instructions.
```
### Defeating DMA
- EXAMPLE
- This one is fun tbh
```
Defeating DMA — Reversing Method

Core question at every step:
"Where did this value come from?"
Always look ABOVE the current instruction.
Code runs top to bottom → values are set before they're used.

The methodology:
1. Breakpoint pops on instruction that touches gold
   → identify which register holds the gold address
   → only follow THAT register (ignore all others)

2. Scroll UP → find where that register was assigned
   → if assigned from another register → follow that one
   → if assigned inside a called function → step INTO it

3. Keep substituting backwards:
   gold = [eax + 4]
   eax  = [ecx + 60] + 0xA90
   therefore: gold = [[ecx + 60] + 0xA90] + 4

4. At each new register → test if it's constant:
   → note its current value
   → note the instruction ADDRESS that sets it
     (code addresses are constant, data addresses are not)
   → restart game completely
   → breakpoint at same instruction address
   → trigger same event
   → same value? → BASE POINTER FOUND → STOP
   → different value? → keep going up the chain

5. Verify with Cheat Engine:
   Add Address Manually → check Pointer
   Enter base pointer + all offsets collected
   Should resolve to current gold value ✅
   Restart game → pointer updates automatically ✅

Final result for Wesnoth:
  Base: 0x017EED18 (constant)
  Offsets: +0xA90, then +4
  [[0x017EED18] + 0xA90] + 4 = gold address always
```

# Programming
There are three main types of game hacks that can be programmed. These are:

- ==External executables== : stand-alone programs that can be executed normally. These executables use functions built into Windows, known as Application Programming Interfaces (API’s), to read and modify memory of another executable.

- ==Injected DLL’s (dynamic-link libraries)== :  need to be loaded into the game’s memory in some way. Once loaded, they execute within the memory of the game and can directly access the game’s memory through pointers

- ==Custom wrappers== : used when creating hacks that target the game’s drawing libraries, such as DirectX and OpenGL. By loading a custom version of these libraries that “wrap” the original functionality, we can cause the game’s drawing logic to be altered.

## External Memory Hack

- So we will be using the Windows API to make our hacks, so we need to include the header for the windows API: 
	- `#include <Windows.h>`

### Reading values
- We need to read several values, The API to read another process’s memory is called [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) 

> This documentation describes how the API works, including what parameters it takes and what values it returns.

> We will also use The [Win32 Coding Style Conventions](https://learn.microsoft.com/en-us/windows/win32/stg/coding-style-conventions)documentation, which provides information on how each parameter is formatted and named.

- ==**ReadProcessMemory**’s== function definition is:
```cpp
BOOL ReadProcessMemory(
    HANDLE  hProcess,
    LPCVOID lpBaseAddress,
    LPVOID  lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesRead
);
```

- So :
```
WHAT WE HAVE vs WHAT WE NEED
──────────────────────────────
  lpBaseAddress  → we have this: 0x017EECB8 (base pointer)
  nSize          → we know this: 4 bytes (size of a register)
  hProcess       → DON'T have yet → next lesson
  lpBuffer       → we create this ourselves (DWORD variable)
  lpNumberOfBytesRead → we create this ourselves (DWORD variable)

════════════════════════════════════════════════

THE CODE SO FAR
────────────────
  #include <Windows.h>

  int main(int argc, char** argv) {

      DWORD gold_value = 0;    ← buffer for the result
      DWORD bytes_read = 0;    ← buffer for bytes actually read

      ReadProcessMemory(
          wesnoth_process,     ← TODO: get this next lesson
          0x017EECB8,          ← our base pointer
          &gold_value,         ← & because API expects a POINTER
          4,                   ← read 4 bytes (DWORD = 32 bits)
          &bytes_read          ← & because API expects a POINTER
      );

      return 0;
  }

════════════════════════════════════════════════

KEY CONCEPTS
─────────────
DWORD = 32 bits = 4 bytes
→ matches the size of registers we saw while reversing
→ correct size to hold our gold value

Why & before gold_value and bytes_read?
→ ReadProcessMemory doesn't want the value of those variables
→ it wants to WRITE INTO them
→ so we pass their ADDRESS using &
→ API then fills them in for us after execution

════════════════════════════════════════════════

MISSING PIECE
──────────────
wesnoth_process (the HANDLE) is still unknown.
A HANDLE = a reference to an open process in Windows.
We need to ask Windows for a handle to Wesnoth.
→ covered in next section
```

### Opening Processes
- So we said we need the `wesnoth_process` handle, we can use an API called [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess), it's definition is :
``` cpp
HANDLE OpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);
```

> NOTE : this API returns a ==HANDLE== 

- Looking at the documentation, we want our ==desired access== (first param) to be ==**PROCESS_ALL_ACCESS**==, so that we can both read and write to the process. The ==second parameter== does not matter for what we are doing, so we will set it to the value of ==true==. We will need to find the ==last parameter==, so for now, we will create a variable.

- So now our code looks like this :
```cpp
HANDLE wesnoth_process = OpenProcess(PROCESS_ALL_ACCESS, true, process_id);

DWORD gold_value = 0;
DWORD bytes_read = 0;
ReadProcessMemory(wesnoth_process, 0x017EECB8, &gold_value, 4, &bytes_read);
```

- To get the ==Last param== (ProcessId) we will use another API called [GetWindowThreadProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowthreadprocessid) 
	- This API retrieves a process ID when provided with a ==window handle==, which is different than a ==process handle==. The definition for this API is:
```cpp
DWORD GetWindowThreadProcessId(
    HWND    hWnd,
    LPDWORD lpdwProcessId
);
```

- And to get a ==Window handle== we use the API called [FindWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa) 
	- This function takes the name of a window title and returns a handle to the window. The definition is:
```cpp
HWND FindWindowA(
    LPCSTR lpClassName,
    LPCSTR lpWindowName
);
```
- Since we want to search all windows, we will set the first parameter to **NULL**. For the second parameter, we know the name of the Wesnoth window, as it is displayed in the game’s title bar.

- Our final code will be :
```cpp
#include <Windows.h>
#include <tchar.h> // we need it for the _T macro 

int main(int argc, char** argv) {

	HWND wesnoth_window = FindWindow(NULL, _T("The Battle for Wesnoth - 1.14.9"));

	DWORD process_id = 0;
	GetWindowThreadProcessId(wesnoth_window, &process_id);

	HANDLE wesnoth_process = OpenProcess(PROCESS_ALL_ACCESS, true, process_id);


	DWORD gold_value = 0;
	SIZE_T bytes_read = 0;

	ReadProcessMemory(wesnoth_process, reinterpret_cast<LPCVOID>(0x017EECB8), &gold_value, 4, &bytes_read);

	return 0;
}
```

- There are some stuff i changed and it's because of errors :
```
THE TWO ERRORS WE HAD TO FIX
──────────────────────────────
1. FindWindow string → needed to be LPCWSTR not const char*
2. ReadProcessMemory address → needed to be LPCVOID not int

════════════════════════════════════════════════

FIX 1 — THE STRING CAST

Course solution:
  L"The Battle for Wesnoth - 1.14.9"
  → L prefix hardcodes the string as wide characters (UTF-16)
  → works, but ONLY in Unicode mode
  → if you switch to Multi-byte mode → breaks

my solution:
  #include <tchar.h>
  _T("The Battle for Wesnoth - 1.14.9")
  → _T is a macro from tchar.h
  → automatically adapts to the project's character set:
    Unicode mode   → _T becomes L"..." (wide string)
    Multi-byte mode → _T becomes "..."  (normal string)
  → works in BOTH modes without changing the code

WHY mine IS BETTER:
  The course solution is a quick fix.
  _T is the correct Windows programming practice —
  it's what Microsoft actually recommends for portable code.
  Your code will compile correctly regardless of 
  the project's character encoding setting.

════════════════════════════════════════════════

FIX 2 — THE ADDRESS CAST

Course solution:
  (void*)0x017EECB8
  → C-style cast
  → just forces the compiler to accept it
  → no type checking, no warnings
  → can accidentally cast incompatible types silently
  → considered bad practice in modern C++

my solution:
  reinterpret_cast<LPCVOID>(0x017EECB8)
  → C++ style cast
  → explicit about WHAT you're casting TO (LPCVOID specifically)
  → compiler can catch mistakes if types are incompatible
  → code is self-documenting: reader knows exactly
    what type you intend
  → correct tool for casting between pointer types

WHY mine IS BETTER:
  reinterpret_cast is the C++ way.
  (void*) is the C way.
  In C++ code, C-style casts are a code smell —
  they're too permissive and hide potential bugs.
  reinterpret_cast makes the intent explicit and
  lets the compiler do more checking.

════════════════════════════════════════════════

FIX 3 — bytes_read TYPE (you caught this too)

Course solution:
  DWORD bytes_read = 0;
  → DWORD = 32 bits

David's solution:
  SIZE_T bytes_read = 0;
  → SIZE_T = correct type for ReadProcessMemory's last parameter
  → on 32-bit: SIZE_T = 32 bits (same as DWORD)
  → on 64-bit: SIZE_T = 64 bits (DWORD would be wrong)
  → matches the actual function signature exactly

WHY DAVID'S IS BETTER:
  DWORD works on 32-bit and happened to work here.
  SIZE_T is what the function actually expects.
  On a 64-bit process this matters — DWORD would truncate.
  Always match the type the API actually specifies.

════════════════════════════════════════════════

FINAL CODE COMPARISON

Course (works but shortcuts):
  FindWindow(NULL, L"...")          ← hardcoded wide string
  (void*)0x017EECB8                 ← C-style cast
  DWORD bytes_read = 0              ← wrong type technically

David (correct C++ practice):
  #include <tchar.h>
  FindWindow(NULL, _T("..."))       ← portable string macro
  reinterpret_cast<LPCVOID>(...)    ← explicit C++ cast
  SIZE_T bytes_read = 0             ← correct type from signature

════════════════════════════════════════════════
```
### Debugging
- We use Cheat engine to compare the values of the address `0x017EED18` and our `gold_value` variable to see if we are reading the correct value

> Make sure you put a breakpoint on the ==ReadProcessMemory== and then hit the `Local Windows Debugger` button, then hit `F10` and check the debugger

### DMA
- We have already determined the gold address `[[0x017EED18] + 0xA90] + 4`.
- To retrieve the gold address in our program, we can first read the value at `0x017EED18`, then add `0xA90` to that value. We can then read this address and add 4 to it.

- We use the `ReadProcessMemory` again :
```cpp
gold_value += 0xA90;
ReadProcessMemory(wesnoth_process, reinterpret_cast<LPCVOID>(gold_value), &gold_value, 4, &bytes_read);
```
- We can use Cheat engine to verify again, then we add :
	- `gold_value += 4;` 

### Writing Memory
- The API to write to another process’s memory is called [WriteProcessMemory.](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) Its definition is very similar to **ReadProcessMemory**:
```cpp
BOOL WriteProcessMemory(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);
```

> The major difference is that this function writes the value of a buffer into a section of a memory, instead of reading a section of memory into a buffer.

- First we declare two variables for the buffer and the number of bytes written :
```cpp
DWORD new_gold_value = 555;
SIZE_T bytes_written = 0;
```

- Then, we can call ==**WriteProcessMemory**== in an almost identical manner to ==**ReadProcessMemory**==. We again add the `reinterpret_cast<LPVOID>` but this time ==LPVOID== 
```cpp
WriteProcessMemory(wesnoth_process, reinterpret_cast<LPVOID>(gold_value), &new_gold_value, 4, &bytes_written);
```
- That's it you can find the full code in my [Github]()