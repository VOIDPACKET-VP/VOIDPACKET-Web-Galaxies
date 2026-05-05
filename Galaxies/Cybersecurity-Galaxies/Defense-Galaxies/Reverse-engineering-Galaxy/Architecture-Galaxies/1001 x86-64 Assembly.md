# Introduction
## Binary to hex to decimal
```
			Decimal              Binary                 Hexadecimal 
			00                   0000b                     0x00  
			01                   0001b                     0x01  
			02                   0010b                     0x02  
			03                   0011b                     0x03  
			04                   0100b                     0x04  
			05                   0101b                     0x05  
			06                   0110b                     0x06  
			07                   0111b                     0x07  
			08                   1000b                     0x08  
			09                   1001b                     0x09  
			10                   1010b                     0x0A  
			11                   1011b                     0x0B  
			12                   1100b                     0x0C  
			13                   1101b                     0x0D  
			14                   1110b                     0x0E  
			15                   1111b                     0x0F
```

## Background: Endianness
- It's basically what part of the value should be stored at the lowest address
### Little Endian
- Little endianness is storing the least significant bytes (the `little end` of the value) at the lowest address
- EXAMPLES :
	1. Intel
### Big Endian
- It's the opposite, we store the `Big End `first : the most significant bytes at the lowest address
- EXMAPLES :
	1. Network traffic
	2. Many RISC systems (PowerPC, SPARC, MIPS), these now can be configured (Bi-endian)
	3. ARM (was little endian, now it's big endian)

- NOTES :
  - Endianness applies to `memory` not `registers`
	  - So `registers` will always be shown in `Big Endian`
	  - The difference is in the order in which they go to the `memory addresses`
  - Endianness applies to `bytes` not `bits` 
  - `char` don't have problem with `endianness` cause they only have `1 byte` 	
![[Screenshot 2026-04-25 202538.png]]
- This is how `Endianness` is expressed inside a debugger
![[Screenshot 2026-04-25 202742.png]]
- NOTE : if you set the debugger to display things in `2, 4 or 8 bytes` at a time, it will typically take those chunks and display then each `big endian` order


- In This course, the memory addresses will represented like this :
	- `HIGH memory addresses` will be on TOP
	- `LOW memory addresses` will be in the BOTTOM

## Computer Registers
### Memory Hierarchy
- Here is a image representing it
![[Screenshot 2026-04-25 203213.png]]
- What we care about is the section in the TOP : `Processor registers`
### x86-64 General Purpose Registers
- Registers are small memory storage areas built into the processor (still volatile memory)
	- On x86-32, register are 32 bits wide
	- On x86-64,  register are 64 bits wide
- Here you can see the evolution of registers
	- It started with: 
		1. the `AL` also known as `R0B ` : 8 bit wide
		2. Then `AX` `AH` `AL` : 16 bit wide
		3. Then Added `EAX`, now it's a 32 bit wide
		4. Finally added the `RAX` making it 64 bit wide
![[Screenshot 2026-04-25 204303.png]]

- Here is a registers Cheat sheet showing all different registers
![[CheatSheet_x86-64_Registers.pdf]]

- NOTE : disassemblers will not use the `R<number>` naming convention, instead they use the: `RAX, RCX etc.`  naming convention
- You might see that some of the sub-registers `SPL, BPL etc.` are in blue not Yellow that's because :
	- they did not originally have a way to be accessed by their lowest byte in the 16 bit implementation of Intel.
	- Others that are colored differently than blue can be accessed by their lowest byte
### Intel recommended register conventions
- Remember, registers don't have to be used this way, here are intel's suggestions :
	- `RAX` => Stores function return values
	- `RBX` => Base pointer to the data section
	- `RCX` => Counter for string and loop operations
	- `RDX` => I/O pointer
	- `RSI` => Source Index pointer for string
	- `RDI` => Destination Index pointer for string operations
	- `RSP` => Stack (top) pointer
	- `RBP` => Stack frame base pointer
	- `RIP` => Pointer to next instruction to execute ("instruction pointer")
- Here you can see [Microsoft compiler register conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-160)

## Your first Instruction : No Operation (NOP)
- This instruction doesn't take any registers, any values, it doesn't take anything
- Mostly used to pad/align bytes, or delay times
- Attackers use it to make simple exploits more reliable
- NOP can be from 1 to 9 bytes long

## The Stack
- A Stack is a `Last-In-First-Out (LIFO)` DATA structure where data is `pushed` on the top of the stack and `popped` off the top
	- Like when you stack Books one on top of the other, the only way to access the bottom book is by popping off the upper books
- It's set by the OS when a program starts, it's a conceptual area of main memory (RAM)
- By convention the STACK grows toward lower memory addresses. Adding something to the stack means the top of the stack is now at the lower memory address
	- The HEAP is the Opposite : grows toward Upper (Big endian) memory addresses
- So in Process memory a stack grows down, the Heap grows up, if we fill them they will collide and the program will have to be terminated
![[Screenshot 2026-04-25 230309.png]]

- In the case of Intel :
	- `RSP` points to the top of the stack : the lowest address which is being used
		- While data will exist at addresses beyond the top of the stack, they are considered undefined and shouldn't be used in program execution

### WHAT CAN WE FIND IN A STACK
- *Return Addresses* : When a function is called it pushes a `return address` to the Stack so that it knows how to get back to the calling function
- *Local Variables*
- *Arguments (sometimes)*
- *Space chosen by the compiler to save registers* : this way functions can share registers without smashing each other's values 
- *Space chosen by the compiler to save registers* : when he has to juggle too many times in a function
- *Dynamically allocated memory* via `alloca()` 


- Here is a SIMPLE STACK DIAGRAM :
	- Basically when functions are called, a `frame` is pushed in the stack
	- So each function will have it's own `stack frame`, however this will not include any new registers 
![[Screenshot 2026-04-25 231601.png]]

### Instructions : push & pop
- NOTE : on MacOS and Linux you will always see `push` and `pop`, they balance each other and complete each other when used in pairs, However if you use VISUAL STUIDO CODE's disassembler you will not see it, we will answer why later

#### push
- It's a quadword (8 bytes) onto the stack
- It stores data and automatically decrements the stack pointer `RSP` by 8 (allocating space), so the stack goes down to the lower addresses by 8 and so as `RSP`
- In 64-bit execution mode, push can :
	- push the value in a 64-bit register
	- push a 64-bit value from a memory where the memory is given in a form called `r/mX` 
#### r/mX
- It's a term made up by the Instructor of this course to refer to anywhere we see `r/m8`, `r/m16`, `r/m32`, `r/m64` in the Intel Manual
- An `r/mX` form is a way to specify either a `register` or a `memory` value
- In Intel SYNTAX, most of the time `[]` means to treat the value within as a memory address and fetch the value at that address *(like dereferencing a pointer)* 
- `r/mX` can take 4 forms:
	1. Register => `rbx`
	2. Memory => `[rbx]` it's like we're saying take the value in `rbx` treat it as a memory address, dereference it and pull that value
	3. Memory (base + index * scale) => `[rbx + rcx * X]`
		- the `X` can be one of the following : `1, 2, 4 or 8`
	4. Memory (base + index * scale + displacement) => `[rbx + rcx * X + Y]` 
		- `Y` can be encoded in 2 ways :
			1. in `1 byte` => `0 to 255`
			2. in `4 bytes` => `0 to 2^32` 
		- This has natural applicability to multi-dimensional array indexing, array of structs etc.

- NOTE : 
	- From now on if you hear *instructions support access to memory* it means memory is going to be encoded in an `r/mX` form
	- And when you hear `r/mX` it means something that can be as simple as a single `register` or as complicated as a memory address calculation in that form :  `[rbx + rcx * X + Y]`
	- You will also see the back tick symbol being used when writing 64 bit numbers, this is only supported by `WinDbg`, it just helps see that it's a 64-bit not something else  :
![[Screenshot 2026-04-25 235201.png]]

- Here is an EXAMPLE of what happens when we execute the `push` command :
![[Screenshot 2026-04-25 235334.png]]

#### pop
- It pops a value from the stack, so retrieves that data and increments the stack pointer (deallocating space).
- In 64-bit execution mode, pop can :
	- pop the value in a 64-bit register
	- pop a 64-bit value from a memory where the memory is given in a form called `r/mX` 
- Here is an EXAMPLE of what happens when we execute the `pop` command :
![[Screenshot 2026-04-25 235808.png]]

- NOTE :
	- That `undef` in red, doesn't mean that the data that was there is gone, it's still their, just compilers shouldn't access memory beyond the stack

### push and pop in 32-bit
![[Screenshot 2026-04-26 000117.png]]

### CHALLENGE :
#### Canonical orientation, rbp at top, rsp at bottom
**HIGH ADDRESSES    
0ddba11 <- RBP  
================  
ba5eba11  
================  
de1e7ed  
================  
5a1ad  
================  
be5077ed <- RSP  
================  
LOW ADDRESSES

**What is the offset to de1e7ed ?** 
- From `RSP` : `rsp+0x10` => 0x10 is 16 in hex, remember every entry is 8 bytes since it's 64-bit architecture
- From `RBP` : `rbp-0x10` 
- If the entry is below, then `-` if above then `+`

#### Canonical orientation, rbp and rsp move around
HIGH ADDRESSES 
7a7700 
================ 
effab1e <- RSP 
================ 
70ffeeC0ffee 
================ 
7E55E11A7ED70AD5 
================
f00d <- RBP 
================ 
f100ded 
================ 
10ca1e 
================ 
B1ade3 
================ 
LOW ADDRESSES 

What is the offset to 10ca1e ?
- Answer => `rsp-0x28 or rbp-0x10`

- There might be a Horizontal representation, in this case you don't move up or down, you move right or left, and depending on where the LOW ADDRESSES are and HIGH ADDRESSES are, you subtract or add 
![[Screenshot 2026-04-26 155040.png]]

## Calling Functions
### Instructions: call, ret, mov, add, sub
#### call
- It transfers control to a different function; in a way that once the function is finished we can pick up where we left off
	- It does that by pushing the address (`return address`) of the next instruction onto the stack (`rsp` down by 8)
		- Which will be used by the return command `ret`
	- Then it changes `RIP` to the address given in the instruction : address of the function we wanna call
- Destination address for the target function can be specified in multiple ways :
	- Absolute address
	- Relative address (relative to the end of the instruction, or some other register)
	- We're not gonna see the difference in encoding of these most of the time
#### ret
- Every `call` has it's `ret`, it comes in 2 forms :
	- Either it pops the top of the stack into `RIP` (REMEMBER `pop` implicitly increments stack pointer `RSP`)
		- In this form, SYNTAX is simply `ret`
	- Or it does the same thing as before, but we can add bytes to `RSP` 
		- Syntax : `ret 0x8` or `ret 0x20` etc.
		- This won't be seen as much, but it is common in Windows API
#### Intel vs AT&T Syntax 
- INTEL : `Destination` followed by `Source(s)` 
	- Windows systems
	- Like assigning variables in programing `int c = 3 + 5;` 
	- EXAMPLE : `mov rbp, rsp` : `rbp` is ``Destination`` and `rsp` is `Source`, `mov` is the `command` (we'll cover it in a bit)
- AT&T : `Source(s)` followed by `Destination` 
	- Unix system
	- Like in elementary school : `1 + 2 = 3` 
	- EXAMPLE : `add $0x14, %rsp` 
	- In AT&T, we add `%`  to registers and `$` to immediates (constant values) 
- Here we'll prefer Intel, but you should know both

#### mov
- It moves stuff:
	- register to register
	- memory to register and vice versa
	- immediate to register, immediate to memory
- Never memory to memory
- Memory addresses are given in `r/mX` form
![[Screenshot 2026-04-26 162829.png]]
#### add and sub
- They add, and subtract
- Destination operand can be `r/mX` or `register` 
- Source operand can be `r/mX` or `register` or `immediate` 
- We can have Source AND Destination as `r/mX`s, because that allow for memory to memory which isn't allowed on x86
- EXAMPLE :
	- `add rsp, 8` => `rsp = rsp + 8` 

