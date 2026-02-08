# Hash Tables
- So a `hash table` is an `array` with a `hash function` 
- Used to index large amount of data
- Address of each key is calculated using the key itself
- Collisions are resolved with open or closed addressing
- Hashing is widely used in DB indexing, compilers, caching, password authentication and more ...
- Insertion, deletion and retrieval of data occur in constant time : `O(1)` (only in the best case scenarios)
### **Hash Functions**
- the latter is a calculation applied to a key to transform it into a very small index number that corresponds to a position in a hash table : the index is in fact an address.
	- For numeric keys, it's common to take the key and divide it by the number of available addresses `n` and take the remainder : `address = key % n`
	- For alphanumeric keys, we divide the sum of ASCII codes in a key by the number of available addresses `n` and take the remainder
	- etc.
- A hash function has to :
	1. Minimize collisions 
	2. Uniform distribution of hash values
	3. Easy to calculate
	4. Resolve any collisions
	5. A hash function for security must be deterministic but resistant to "Hash Flooding" (DoS attacks).
		1. In a real web server, if an attacker knows your hash function is weak, they can send thousands of keys that all generate the **same index**. This turns your $O(1)$ table into a giant $O(n)$ linked list, spiking the CPU to 100% and crashing the service.
### **Collisions**
- Sometimes when we apply a hash function to 2 keys, it generates the same index for them both, but both items can't go in the same place.
- Resolving a collision by placing an item somewhere different than it's calculated address is called `open addressing` because every address is open to any item
	- There is what's called `closed addressing` it's faster and better than `open addressing` and it's basically instead of doing a linear search to find an empty spot or to find the key in the first place, we basically connect a `linked list` to the `hash table` so every item that wants to go in position 5 will be connected to each other in form of a list 
	- ![Hash table with linked lists](VOIDPACKET-Web-Galaxies/Galaxies/Coding-Galaxies/hash with linked lists.png)
	- But note that if the `load factor` is low it's better to use `linear probing` `(Open addressing)` 
	- The Load Factor ($\alpha$) is $\frac{n}{k}$ where $n$ is entries and $k$ is buckets. When $\alpha > 0.7$, performance drops.
		- In C, you can't just "resize" an array easily. You have to allocate a **new, larger array**, then **re-hash** every single old item into the new positions. It’s a massive "suffer" moment in C coding.
	- When using `open addressing` there are other ways of searching other than `linera probing` :
		1. `Plus 3 rehash` : instead of moving by one slot we move by 3.
		2. `Quadratic probing`  : with every failed attempt at finding an empty slot it will square it > `(attempt number 1)^2` then `(attempt number 2)^2` etc.
	- When `Open addressing` : When deleting , you can't just leave an empty slot `(NULL)`
		- If you delete an item in a linear probe chain, the search for items _after_ it will break (the computer thinks the chain ended). You have to place a **"Tombstone"** (a special marker) to say "something was here, keep looking."
	
-   If you know the `KEYS` in advance you can make a perfect `hash function` that uses all of the possible space

  