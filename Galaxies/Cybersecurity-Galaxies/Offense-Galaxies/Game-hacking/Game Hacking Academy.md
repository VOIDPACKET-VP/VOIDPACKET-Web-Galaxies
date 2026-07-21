
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
### Goal
Recruit units anywhere on the map, not just specific tiles.
### The Problem
We want to modify the right-click context menu so that
selecting "Terrain Description" calls the debug spawn menu instead.
But we don't know WHERE in the code the context menu is handled.
### The Strategy — Bubbling Up
We already know ONE location deep in the call stack:
the gold subtraction code from the previous hack.
We use that as our entry point and climb UP the call stack
until we reach the function that handles the context menu.

Think of it like this:

```
handle_context_menu() ← we want to get HERE  
recruit_unit()  
find_unit_in_unit_list()  
subtract_unit_cost()  
subtract_gold() ← we start HERE (we know this address)
```

We climb from the bottom to the top, one function at a time.

---

### Key Concepts
#### Call and Return in Assembly
When a function is called in assembly:
- `call some_address` → jumps INTO the function
  and pushes the return address onto the stack
  so the CPU knows where to come back to
- `retn` → jumps BACK to whoever called this function
  by popping that return address off the stack

This is how the CPU knows where to go after a function finishes.
#### Step Into vs Step Over
Two ways to move through code in ==x64dbg==:
- ==**Step Into**== → if the current instruction is a `call`,
  follow it and enter the function
- ==**Step Over**== → if the current instruction is a `call`,
  execute the whole function and land on the next line
  without going inside it

Step Over is used when you don't care about a function's internals
and just want to move past it quickly.
#### Execute Till Return
A feature in x64dbg that runs the program until the next `retn` instruction is hit. Used to fast-forward to the end of the current function so you can then Step Over the return and land in the caller.

---
### The Bubbling Up Workflow
#### Why look ABOVE the breakpoint pop location?
Code runs top to bottom. If our breakpoint popped on instruction X, everything ABOVE X already ran. Everything below X hasn't run yet. So to find where a register was set, we always look ABOVE where we currently are.
#### Why follow a specific register and not just any register?
We only follow the register that appears
in the instruction we care about.
Example: if gold is at `[eax + 4]`,
then eax leads to gold. ebx and ecx are irrelevant here.
Always identify WHICH register holds your target
and follow only that one backwards.

#### Step by step:
1. Set breakpoint at the known gold subtraction address (`0x007ccd9e`)
2. Recruit a unit in game → breakpoint pops
3. Click **Execute till return** → lands on `retn`
4. Click **Step Over** → now we're in the function that called subtract_gold
5. Repeat: Execute till return → Step Over
6. Keep going until the code pattern changes to something that looks like branching

---
### Recognizing the Context Menu Function
#### What to look for
A switch-like structure in assembly looks like this:
```asm
call dword ptr ds:[eax+0x??]
jmp  to_end
call dword ptr ds:[eax+0x??]
jmp  to_end
call dword ptr ds:[eax+0x??]
jmp  to_end
```
Multiple calls followed by jumps = branching = menu handler.
#### How to verify you found the right function
1. NOP out the call you just stepped out of
2. Go back into the game and try to recruit a unit
3. If nothing happens → you NOPed the recruit call → correct location ✅
4. Go back to x64dbg → right-click → **Restore selection** → undo the NOP
5. Now make your real change

> The NOP test is how you CONFIRM a location before committing to a change.

---
### The Big Discovery — Function Pointer Arrays

The game doesn't use a switch statement like we assumed.
Instead it uses an **array of function pointers**:

```cpp
// What the game's code probably looks like:
void* context_menu_functions[] = {
    terrain_description,   // offset 0x28
    recruit_unit,          // offset 0x54
    debug_spawn_menu,      // offset 0x68
    ...
};

context_menu_functions[option_selected]();
```

In assembly this looks like:
```asm
call dword ptr ds:[eax + 0x28]   ; terrain description
call dword ptr ds:[eax + 0x54]   ; recruit unit
call dword ptr ds:[eax + 0x68]   ; debug spawn menu
```

Each offset is a multiple of 4 because function pointers
are 4 bytes wide (32-bit).
The offset = which slot in the array = which menu action.
#### How we found the offsets
We already knew recruit = `0x54` from bubbling up.
We then changed `0x54` to other multiples of 4
and observed what happened in game:
- `0x28` → terrain description appeared
- `0x68` → debug spawn menu appeared

> This is brute-force offset exploration — try values, observe results.

---
### The Hack

**What we changed:**
Found the terrain description call (offset `0x28`)
and changed it to `0x68` (debug spawn menu).

**Why terrain description?**
Because it's available on ANY tile.
Recruit is only available on specific tiles.
By redirecting terrain description → debug menu,
we can now spawn units from any tile on the map.

**Result:**
Select any tile → right-click → Terrain Description
→ Debug spawn menu opens → place any unit anywhere ✅
### Important Note on Code Addresses
- Unlike variable addresses (which change every restart due to DMA),**code addresses are constant**.
- The gold subtraction code will always be at `0x007ccd9e`. This is why we can reuse the same address across sessions when working with code instead of data.

---

## Code Caves
- So far the hacks we did only included changing 1 instruction, but what if we want to replace multiple instructions. That's where a ==Code Cave=== comes in.
- It's a section of the game’s memory that we fill with instructions. Most games will have large sections of unused memory between functions or at the end of the executable. These locations are perfect for creating a code cave in.
- So what you need to know is the following :
```
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


> Key rule: only modify what you need, never leave registers in a different state than you found them

```
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

- We'll be using the Windows API to make our hacks, so we need to include the header for the windows API: 
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
HWND FindWindow(
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
- That's it you can find the full code in my [Github](https://github.com/VOIDPACKET-VP/voidPacketProjects/blob/main/CyberProjects/GameHacks/wesnoth_external_memory_hack.cpp) 

## DLL Memory Hack
- Using ==external programs== has big limits. You have to convert data carefully, and dealing with complex game files or whole character classes is too difficult. External programs also cannot easily listen to game buttons you press, and adding custom code requires manually translating everything into opcodes

- To fix this, you can ==inject a DLL== directly into the game. Once inside, the DLL becomes part of the game itself. This lets it read and change any data instantly using pointers. It can also run its own background tasks to watch for player button presses and handle complex data smoothly.

### Creating DLLs
- You create the project like you always do, create the `main.cpp`, then right click on the project > properties > General > Then change the _Configuration Type_ from _Application_ to _Dynamic Library_ 
### DLL Basics
#### What is a DLL?
- ==**They can't run on their own==:** A DLL (Dynamic Link Library) cannot be executed by itself. It has to be loaded inside a normal executable program (like a `.exe`).
- ==**They save time and space==:** Developers put common functions into a DLL so multiple programs can share them. This means developers don't have to rewrite the same code over and over.
- ==**Easy updates==:** For example, the Windows file `user32.dll` handles pop-up alerts. If Microsoft updates how an alert looks inside that DLL, every single program using it automatically gets the new look without needing to change its own code.
#### How DLLs Differ from Normal Programs
1. **Different main function:** Instead of a standard `main` function, they use `DllMain`.
2. **Triggered by events:** `DllMain` automatically runs whenever a program loads or unloads the DLL.
3. **Shared memory:** DLLs run _inside_ the memory of the program that loaded them.

- The [DllMain](https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain) function has different parameters from a **main** function. Its definition is:

```cpp
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
);
```

The setting called `fdwReason` is used by the function to know _why_ it was called. When a DLL is first loaded into a program, this setting equals `1` (also known as `DLL_PROCESS_ATTACH`). In hacking, you check for this value to make sure your code only runs once.

#### DLL Injection in Hacking
Because DLLs must run inside another program's memory, hackers have to force a target program to load their malicious DLL. This process is called **DLL injection**.

It can be tricky to know if an injection actually worked. While you could use a debugger to look deep inside the program's loaded modules, that takes a lot of time. A simpler testing method—which is used here—is to code the DLL to display an ==obvious visual indicator== (like a pop-up alert) the moment it successfully injects.

### MessageBox
- It displays a message box in a process. The [definition](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox) for this function is:

```cpp
int MessageBox(
    HWND    hWnd,
    LPCTSTR lpText,
    LPCTSTR lpCaption,
    UINT    uType
);
```
- Due to how C++ handles parameter casting, we can ignore the types for these values :
	- `MessageBox(0,0,0,0);`
	- This will display a blank message box with an _Error_ title and no text.

- We can use this behavior to ensure that our DLL is injected successfully into ==Wesnoth==, so inside `main.cpp` add this :
```cpp
#include <Windows.h>
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {

	MessageBox(0,0,0,0);	
	return true;
	
}
```

### Injecting DLL's
```
DLL Injection

════════════════════════════════════════════════

WHAT IS DLL INJECTION?
────────────────────────
Normally a program loads a DLL using LoadLibrary API inside its own code.
But since we're not modifying Wesnoth's source code we need to force our DLL into the process from outside. This is called DLL injection.

════════════════════════════════════════════════

METHOD 1 — DLL INJECTOR (the proper way)
──────────────────────────────────────────
An external program that:
1. Creates a thread INSIDE the target process
   using CreateRemoteThread API
2. That thread calls LoadLibrary inside the process
3. Our DLL gets loaded

→ Covered in the DLL Injector lesson later

════════════════════════════════════════════════

METHOD 2 — AppInit_DLLs (what we use in this lesson)
──────────────────────────────────────────────────────
A Windows feature that automatically injects
any DLL you specify into EVERY process that starts.
Controlled via the Windows Registry.

Important limitations:
→ Windows 10 and below ONLY
→ Requires Secure Boot to be DISABLED
   (VirtualBox disables it by default — fine for VMs)
   (real hardware → disable in BIOS)
→ Windows flags this because malware loves it

════════════════════════════════════════════════

SETTING IT UP — REGISTRY CHANGES
──────────────────────────────────
Open regedit and navigate to:
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\
Microsoft\Windows NT\CurrentVersion\Windows

Two values to change:

1. AppInit_DLLs
   → set value = full path to your DLL
   → Windows will inject this DLL into every new process

2. LoadAppInit_DLLs
   → set to 1 = ENABLED
   → set to 0 = DISABLED

After making these changes:
start Wesnoth → message boxes appear
→ confirms DLL was injected and is loading/unloading ✅

════════════════════════════════════════════════

CRITICAL WORKFLOW RULE
───────────────────────
AppInit_DLLs injects into EVERY new process.
Including the build process when you recompile your DLL.
This will cause conflicts and issues.

Correct workflow every time you make changes:

  1. Set LoadAppInit_DLLs → 0  (disable)
  2. Build/recompile your DLL
  3. Set LoadAppInit_DLLs → 1  (re-enable)
  4. Start Wesnoth to test

Never build while injection is enabled.

════════════════════════════════════════════════

CONNECTION TO MALWARE DEV
──────────────────────────
AppInit_DLLs is a classic malware persistence technique.
Malware sets its DLL path in AppInit_DLLs
→ gets injected into every process automatically on startup
→ survives reboots via registry
```

### Creating Threads
- We want our DLL to wait for a key press before changing the gold, and to do this we need to create a ==Thread== in the ==Wesnoth process== 

> The Thread will run until the game is exited

- Before we create it we need to make sure that our ==DLLMain== only execute our code when our DLL is first loaded into the process, which will ensure that only One Thread is created
	- We do this by checking the ==fdwReason== param:
```cpp
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Code to execute when the process is loaded
    }

    return true;
}
```

- Now, to create Threads in a process, we use the [CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) API, it's definition is :
```cpp
HANDLE CreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
);
```

 > Since we're creating a ==Thread== within Wesnoth with no special attributes, we can ignore most of these parameters. The only parameter we are concerned with is **==lpStartAddress==** , which represents *the function we want to execute when the thread is started.* 
 
 - That function doesn't have to return anything, so it will be of type ==void==
```cpp
void injected_thread() {

}

BOOL WINAPI DLLMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	if (fdwReason == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(injected_thread), NULL, 0, NULL);
	}
	
	return TRUE;
}
```

- When loaded, this code will create a thread that will execute the ==**injected_thread**== function and then exit. To ensure that our thread remains active, we will use an infinite **while** loop in our ==**injected_thread**== function:

```cpp
while (true) {
    Sleep(1);
}
```

- This while loop will run until our thread is exited by the closure of the game. To prevent our thread from causing slowdowns, we can use the **Sleep** API to pause its execution for a millisecond.

### Detecting Key Presses
- We can use the [GetAsyncKeyState](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate) API, it takes a single param:
	- the key to check for

> If the key is down, it will return true. Otherwise, it will return false

- Our function code will be :
```cpp
while (true) {
    if (GetAsyncKeyState('M')) {
        // Change the player's gold
    }

    Sleep(1);
}
```

> Note that **GetAsyncKeyState** will constantly return true if the key is held down. So if we want to toggle a value off and on in the future, we will need to account for this behavior.

### Pointers
```
WHY POINTERS INSTEAD OF ReadProcessMemory?
────────────────────────────────────────────
In the external hack, we used ReadProcessMemory/WriteProcessMemory
because our program was OUTSIDE Wesnoth.

Now our DLL is INJECTED into Wesnoth.
We share the same memory space as the game.
So we can access memory directly using pointers —
no need for ReadProcessMemory at all.
Same addresses and offsets as before, cleaner access.

════════════════════════════════════════════════

READING THE POINTER CHAIN
───────────────────────────
Remember our chain from the DMA lesson:
[[0x017EED18] + 0xA90] + 4 = gold address

Step 1 — get player base:
   DWORD* player_base = (DWORD*)0x017EED18;
   → declare a pointer that points to address 0x017EED18
   → *player_base = the value stored there (player class address)

Step 2 — get game base:
   DWORD* game_base = (DWORD*)(*player_base + 0xA90);
   → dereference player_base to get the player class address
   → add offset 0xA90 to reach the game object
   → game_base now points to the game object

Step 3 — get gold and change it:
   DWORD* gold = (DWORD*)(*game_base + 4);
   *gold = 999;
   → dereference game_base + offset 4 = gold address
   → dereference gold pointer and SET the value to 999
   → gold is now 999 in the game ✅

════════════════════════════════════════════════

HOW IT READS IN PLAIN ENGLISH
───────────────────────────────
   "Go to address 0x017EED18,
    read what's there (player base),
    add 0xA90 to get to the game object,
    read what's there (game base),
    add 4 to get to gold,
    write 999 there."

Same chain we built by reversing.
Now expressed purely in C++ pointers.

════════════════════════════════════════════════

TRIGGER — HOW THE HACK ACTIVATES
──────────────────────────────────
The hack is triggered by pressing M in game
(from the GetAsyncKeyState code in the thread).
After pressing M and moving the camera,
gold updates to 999 ✅
```

> Make sure you ==build the DLL== then set ==LoadAppInit_DLLs to 1== then fire up the game

## Code Cave & DLL's
- To create a ==code cave== inside a ==DLL==, we need to :
	1. Create a code cave in our DLL
	2. Modify the ==opcodes== in the Terrain Description to ==jmp== to this code cave inside our DLL

### Assembly in C++
- C++ allows us to insert ==assembly== in a ==C++ source file==, to do this we use the ==`__asm` keyword== :
```cpp
__asm {
	pushad
}
```

> This assembly will not be modified during the compiling steps

- We can also mix C++ and assembly in a function :
```cpp
// the following code will save all registers, create a variable **x**, add 1 to it, and then restore all registers:

__asm {
	pushad
}

int x = 0;
x += 1;

__asm {
	popad
}
```

> Variables declared in C++ can be referenced in these assembly blocks. ==We will use this behavior to program our hack, SO REMEMBER IT==

### Assembled Functions
- Since we need to jump to our code cave we need to know it's location, the easiest way to do this in C++ is by declaring our ==code cave=== as a ==function==. Then we can use the ==&== to retrieve its address

- However due to how functions get assembled :
	- A stack frame is created which adds extra instructions, which can corrupt our game when we jump into our code cave
```assembly
codecave:
    push ebp
    mov ebp, esp
    ...
    mov esp, ebp
    pop ebp
    ret
```
We use the ==`__declspec` keyword== combined with the ==`naked` keyword== which makes ==the compiler not add a stack frame==

> ==Stack frames== allow the compiler to easily ==offset and compute== the location of ==local variables== and ==function arguments==

### Cave Skeleton
- Alright, now lets' begin creating our code cave:
	- Create a DLL in Visual Studio
	- Add our function :
```cpp
__declspec(naked) void codecave() {
	
}
```

- As we discussed, the first step when creating a code cave is to ==save and restore the registers== and then ==restore the overwritten instructions== :
```assembly
pushad
/// HACK GOES HERE ///
popad
mov eax, dword ptr ds:[ecx]
lea esi,dword ptr ds:[esi]
jmp 0xCCAF90
```

- In our DLL, we'll create 2 separate blocks of assembly :
	1. Save all the registers
	2. Restore the registers and then execute the original instructions we have overwritten

```cpp
__asm {
    pushad
}

// code to modify gold

__asm {
    popad
    mov eax, dword ptr ds:[ecx]
    lea esi,dword ptr ds:[esi]
    jmp 0xCCAF90
}
```

> We cannot jump directly to a ==static address== because the compiler does not know the jump's length or how to encode the instruction, resulting in a compilation error. To fix this, we must ==store the static address inside a variable== so the compiler can resolve it. Because this code runs inside a ==code cave with no stack frame==, you ==cannot declare local variables== and must instead ==declare the address as a global== `DWORD` variable 

- So right now our code will look like this :
```cpp
#include <Windows.h>

DWORD ret_address = 0xCCAF90;

__declspec(naked) void codecave() {
    __asm {
        pushad
    }

    // OUR HACK GOES HERE

    __asm {
        popad
        mov eax, dword ptr ds:[ecx]
        lea esi,dword ptr ds:[esi]
        jmp ret_address
    }
}
```

### Changing Gold
- We can now use the same approach in ==DLL Memory Hack== :
```cpp
// As Global Variables :
DWORD* player_base;
DWORD* game_base;
DWORD* gold;

// Inside our code cave :
player_base = (DWORD*)0x017EED18;
game_base = (DWORD*)(*player_base + 0xA90);
gold = (DWORD*)(*game_base + 4);
*gold = 888;
```

### Redirection
- To redirect the game's code to our function, we will use an ==unsigned char== pointer targeted at the original hooking location (`0x00CCAF8A`) because this ==type represents 1 byte==, giving you the flexibility to modify individual bytes of game data. Before writing to this code address, we must use the ==VirtualProtect Windows API== to change its default execution-only protection status, which normally blocks outside processes or DLLs from writing data. The modification requires inserting a ==jmp== instruction, which begins with the ==0xE9 opcode== followed by ==4 bytes== that determine the destination. These 4 bytes are not the direct target address but are calculated using ==the formula `new_location - original_location + 5`==.

> Due to ==Endianness== on Windows-compatible CPUs, the resulting calculated value must be ==written into memory== in ==reverse byte order== to match how the CPU reads the opcode

#### Redirection Function
- We'll handle the redirection in the ==DLLMain== function, but first we need to :
	- ==Declare a pointer== to our hook location
	- ==**VirtualProtect** API== requires a parameter to hold the previous protection type. ==We will declare that as well==:
```cpp
DWORD old_protect;
unsigned char* hook_location = ( unsigned char* )0x00CCAF8A;
```

- Next we will change the ==Protection Type== for our ==hook location==, and similar to what we did in the Last code cave lesson, we will need to ==rewrite 6 bytes==

> ==**VirtualProtect** API== has similar parameters to the ==**ReadProcessMemory**== and ==**WriteProcessMemory**== API’s.

```cpp
if (fdwReason == DLL_PROCESS_ATTACH) {
    VirtualProtect((void*)hook_location, 6, PAGE_EXECUTE_READWRITE, &old_protect);
    // REDIRECTION CODE GOES HERE
}

return true;
```

- To write a relative jump (`JMP`) hook to a code cave, we first set the initial byte at the target location to `0xE9` (the JMP opcode) 
```cpp
*hook_location = 0xE9;
```
- Then calculate the 4-byte destination offset using the formula we tested before : ==new_location - original_location + 5==
```cpp
*(hook_location + 1) = &codecave - (hook_location + 5);
```
- But because the location pointer is originally defined as a ==1-byte `unsigned char`==, we must explicitly cast it to a ==4-byte `DWORD*` pointer== so the compiler writes the full offset instead of cutting it off, also cast the other variables to ==**DWORD**’s==
```cpp
*(DWORD*)(hook_location + 1) = (DWORD)&codecave - ((DWORD)hook_location + 5);
```
- Finally, just like we did in the previous lesson, we need to make the ==sixth byte a **nop** (index 5)== to cleanly pad out the remaining space from the original instruction.
```cpp
*(hook_location + 5) = 0x90;
```
- Once these memory modifications are complete, the DLL can be built and injected into the game, where selecting any tile's Terrain Description will successfully trigger the hook and set your gold value to 888.

- You can Check the Full code [here](https://github.com/VOIDPACKET-VP/voidPacketProjects/blob/main/CyberProjects/GameHacks/wesnoth_code_cave_DLL_hack.cpp) 

## Printing Text
- Our goal here is to ==print our own text in Wesnoth==, we will do that by locating a section of code responsible for printing text, then use a code cave to modify the game's memory to display our text

- ==NOTE== : There are multiple approaches to print our own text >
	1. Use an external overlay.
	2. Create a code cave inside the game’s main display loop and call the function responsible for displaying text.
	3. Create a code cave inside a function responsible for displaying text and modify the text about to be displayed.
- Here we'll use the third option cause it's the easiest in Wesnoth

### Locating Text
- We need to locate the game’s code that is responsible for displaying text, so obviously the first thing to do is to ==find a string of letters that appears in the game==
	- For this example we'll use the _Terrain Description_ text, specifically the description for the _Ford_ tile

- So select a map that has _Ford_ tiles on it (e.g. _Den of Onis_)
- We can use Cheat Engine to find the TEXT's address like we always do.

> To narrow down which address represents the string we are interested in, change the first letter of every string. After changing these values, go back into Wesnoth and examine the terrain description again.

### Locating PrintText
- We do know that the print text function must access this text in some way to print it, so we ==set a breakpoint on a byte== of the text :
	1. Select and right click One Byte in the `Dump` section
	2. Breakpoint > Hardware, Access > Byte
- Now if we go back into Wesnoth and invoke the _Terrain Description_ action again our ==breakpoint will pop== immediately:
	- We see that the instruction it popped into is :
		- ==`rep movsb`== : loop responsible for moving each byte (of text) into a buffer
- Now we need to navigate to the code that called this lower-level code, which we can do by using :
	1. ==Execute until return== Button
	2. ==Step over== Button

- If we continue execution (==run== button), we notice that this code is called multiple times for each section of the terrain description box.
- To find the function's parameters, we set a breakpoint at `0x005ED114` and trigger the _Terrain Description_ action. The program ==loads the text into the `edx`== register and then ==copies it to the memory location held by `esp`==. This process places the data onto the top of the stack

> ==REMEMBER== : a Stack is a temporary storage area, and functions routinely retrieve data to run their code from it 

### Memory and Endianness
- To locate our dynamically allocated text string, we must first ==invoke the Terrain Description== action to trigger our breakpoint, ==right-click the `edx`== register value, and ==select Follow in Dump== to view the raw memory bytes.

>Even though Cheat Engine and the dump share the same data, the bytes at `edx` initially look "reversed" because Windows CPUs use little-endian format, meaning the least-significant byte is stored first at the lowest memory address.

- Once we recognize that this reversed value is actually the pointer we need, we ==select all those bytes== and ==click Follow in Dump a second time== to finally arrive at our string's true location. To safely reference and use this dynamic memory location in our assembly code cave, we use the
	- `mov eax, dword ptr ds:[edx]` instruction to load that pointer into the `eax` register, allowing us to read the individual bytes of the text.

### Changing Text
- To verify we have the correct method, we will create ==a 5-byte code cave== at `0x01343E1B` by replacing the call at `0x005ED129` with a jump to our redirection point.

> Remember : the **call** at `0x005ED129` is responsible for printing the text and is also 5 bytes long, we will use it as our redirection point.
> And any location near the end of program’s memory will work for our cave location.

- Inside our cave, we will first ==save the registers==, use the ==`ptr ds` keyword to load the text value from `edx` into `eax`==, and then use the ==`inc` operator to increase the value of the first byte of the string== (changing an 'A' to a 'B', for example). Finally, we will ==restore the registers==, ==recreate the original call==, and ==jump back to the original code== :

```assembly
pushad
mov eax, dword ptr ds:[edx]
inc byte ptr ds:[eax]
popad
call wesnoth.5E9630
jmp wesnoth.5ED12E
```

- allowing us to go into Wesnoth and invoke the Terrain Description action multiple times to confirm the text changes and our hack works.

# RTS/RPG Hacks
## Stathack
- A ==Stathack==, also known as ==statistic hack== is a  type of hack that displays information to us about other players, such as their gold or number of units

> Our goal in this lesson is to display the gold of the second player

- Now to do this we need to accomplish ==2 steps== :
	1. Find the second player’s gold.
	2. Print this value to the screen.

### Second Player's Gold
- In the ==Game Fundamentals lesson== we learned that games often store similar data and classes in arrays that get iterated over to locate and update values, and although it's unconfirmed whether Wesnoth uses this pattern, we can apply it as a model to try to find the second player's gold value
- Building on the ==Defeating DMA lesson==, where we determined that the game dynamically allocates player classes from a base pointer and identified both the game's base pointer and the first player's base pointer, we can now closely re-examine that same code to check whether the game stores player classes in an array and, if so, pinpoint the second player's base pointer
- To do this :
	1. set up a local game with two local players, ensure both receive income each turn, 
	2. start the game, attach x64dbg
	3. play one full turn per player so any first-turn initialization code runs
	4. then set a breakpoint at ==0x9B4CE3== (the same call identified previously)
	5. finally end the first player's second turn in Wesnoth, at which point the breakpoint should trigger.

![[Pasted image 20260711190329.png]]
- The value in ==EBX== indicates that this function is invoked for every player each turn, we also know that the value of ==ECX== is the game's base pointer :
	- ==This allows us to assume that the game has an array of player classes.==
- Our next step is to ==determine the size of each player== entry in the array, since the game needs this to advance to the next player, so we ==step into the call at 0x9B4CE3== and trace through it line by line, noting that most of the addresses and values match what we saw when locating the first player's gold address, except near the end where an ==`imul` (signed multiply)== instruction appears—when stepping through as the ==first player `edx` is 0==, but as the ==second player `edx` is 1==, indicating the game uses ==`edx` as a player offset multiplied by 0x270==, with that result then ==added to `eax`== to produce the current player's gold address; using the same base offset technique as before, `[[0x017EED18] + 0xA90]` gets us the game's base pointer, and while ==adding 4 gives the first player's gold address==, ==adding 0x270 + 4 (0x274) gives the second player's gold address==, which we can confirm in Cheat Engine, and finally we update our existing code to use 0x274 instead, as shown: 
```cpp
player_base = (DWORD*)0x017EED18;
game_base = (DWORD*)(*player_base + 0xA90);
gold = (DWORD*)(*game_base + 0x274);
```

### Printing Value
