# What is a Network
- Devices talking to each other, sharing data and trying to get from point A to point B.
- So the whole point is to get a device to talk to another device, when we're talking about 2 devices it's easy, but when we're talking about more we need something called a `Switch` 
## Switch
- A device that connects devices on the same local network
- You would think we solved the problem, but no, once you create more groups of devices or separate networks, we need something that can move traffic between them, enters the `Router`
## Router
- Helps one network talk to another network
---

- Alright, now here are 2 other core devices that are foundational:
## Firewall
- protects networks by allowing good traffic and blocking bad traffic
- This is what you try to hack most of the time, after all a Firewall is just a set of rules
## Wireless Access Point (WAP)
- lets devices connect without cables
- So even if you're devices are wireless, they still need to connect back into the network somehow, the `WAP` takes care of that
	- It takes that network and broadcasts it over the air so your phone, laptop, or tablet can join in.

> **REAL WORLD TIP:** In the real world, don’t get stuck thinking every home setup looks like every business setup. At home, one all-in-one device is normal. In a company, you’ll usually see dedicated switches, dedicated firewalls, dedicated wireless systems, and a lot more complexity. Learn the functions first, then the hardware choices make a whole lot more sense.

# Switch
- Unlike the `HUB` where if a device sends data everybody gets it, a Switch allows devices to communicate fast, cleanly, and with purpose
	- That means less noise, less wasted bandwidth, and a far better network experience overall.
## How a Switch controls traffic
- Now you might ask : How does it know where the recipient device is ?
- Well simply it learns, as devices communicate, the switch builds a little map of which device lives on which port 
	- That map is called : `CAM Table` , `Content Addressable Memory`
	- So the switch watches traffic, looks at the source's `MAC Address` and stores that information, later all the switch's got to do is check the destination's `MAC Address` and forwards the `Frame` to the correct port
## Layer 2, MAC Addresses, Frames
- A switch operates at `Layer 2` of the `OSI Model`, which means it cares about `MAC addresses`, not `IP addresses` (`Layer 3`).
- And when we’re talking about Layer 2 traffic, the proper term for that message is a **frame**. Not a packet.
	- Layer 2 -> Frame
	- Layer 3 -> Packet
- So remember it like this :
  - `Switch = Layer 2 = Frames = MAC addresses` 

> **REAL WORLD TIP:** On the job, if a device can’t reach another device on the same LAN, one of the first places I want to look is the switch’s MAC address table. If the switch hasn’t learned the device, that tells me something is wrong at the physical or data link level, cable, port, NIC, VLAN, something in that world.

# Router
- helps devices talk between different networks.
- Networks are defined by their IP address ranges, which means even though you can physically connect 2 switches together, logically the devices would still be dealing with separate IP networks.
	- So the problem is not these devices are on different switches, it's that those devices are on different IP networks
- Router understands `Layer 3` : where IP addresses live, these IP are used to move packets from one network to another.

> A switch cares about MAC addresses, which are like physical delivery labels inside your local neighborhood. A router cares about IP addresses, which are like the full destination on the map.

## Default Gateway
- Your default gateway is usually the router interface on your local network.
	- It's like an Exit Door to other Networks, you can talk to neighboring devices, but not outside your network
- So when we wanna talk to the outside we send the traffic to the router, then the router checks if it's local or not :
	- If it’s local, it uses `ARP`, which stands for `Address Resolution Protocol`, to discover the other device’s MAC address and hand the frame to the switch. 
		- `ARP` broadcasts "who has this IP?" on the local network, and the device that owns that IP replies with its `MAC address`.
	- If it’s remote, it uses `ARP` to discover the router’s MAC address, because the router is the next stop.

> **REAL WORLD TIP:** When a device can reach local machines but not the internet, one of the first things I check is the default gateway. Wrong gateway, missing gateway, or a gateway that’s down will break off-network communication fast. You’ll look like a wizard for spotting it early, but really you’re just understanding how routing actually works.

## Behind the scenes of the router
- When you build a packet with the destination IP, the IP stays the same from end to end, but the `Layer 2 Frame` (that carries `MAC Addresses`) changes : 
	- First it goes from the sender's MAC Address to the Router's
	- Then the router rebuilds the frame and sends it using it's own MAC Address as the source and the receiver's MAC Address as the destination
- So you can see the `Frame` as the local delivery wrapper :
	- So when the router receives a frame, it strips off the old Layer 2 information, looks at the Layer 3 destination, checks its routing table, and then builds a new frame for the next network
	- And if the router doesn't know the remote device's MAC Address yet, It uses `ARP` to learn it

## DNS
- Stands for `Domain Name System` , it's what translates a friendly name like `voidpacket ecosystem` into an IP Address
	- That's because routers do not route based on names (they're for Humans), routers need Numbers

> DNS lookup first -> then routing -> then delivery -> then response.

# TCP/IP and OSI
- So once upon a time, devices talking to each other was not the natural state of technology, so we had to invent something that would allow that, enters `TCP/IP` and `OSI` 
	- They are network models : organized ways to describe how communication should happen : how data gets packaged, addressed, transmitted, received and understood
## TCP/IP
- So it's a network model : it has standard rules that every device should follow, that's how devices can communicate
- And to make things easier, we divided the communication process into layers or stages instead of one big blob, The `OSI Model`

## OSI 
- Stands for `Open Systems Interconnection`, it's not as standard as the `TCP/IP` but it won the terminology war
- Has 7 layers :
	1. Application
	2. Presentation
	3. Session
	4. Transport
	5. Network
	6. Data Link
	7. Physical
- You might be thinking, "Okay, if TCP/IP is what we actually use, why bother?" well, when we troubleshoot, we use OSI language : `That's a Layer 1 issue," meaning a physical problem` 
- From `Layer 1` to `Layer 4` they map over pretty cleanly : `Physical`, `Data Link`, `Network`, `Transport` 
	- The only difference is at the top, `OSI` separates `Session` and `Presentation`, while `TCP/IP` rolls that functionality into the `Application Layer`

> REAL WORLD TIP: When you're troubleshooting, I don't start by panicking and saying, "The network is broken." You start by asking "What layer is failing ?"

## Why they matter
- By having the models we get a roadmap, a framework so problems don't feel random
- That's why you need to know `TCP/IP` because it's the one devices actually use. Know `OSI` because it's the language network engineers actually speak.

## Real Life Example
1. The moment Johnny types in the website, the application layer kicks in. In plain English, that’s the part where his web browser says, “Hey, I want this website.” In this case, the protocol is **`HTTPS`**, which is the secure version of `HTTP`, the language browsers use to talk to web servers. So before anything hits a cable, the request starts life as application data.

2. From there, the data moves down to the **transport** **layer**, and this is where we decide _how_ the data should travel. Usually that means **`TCP`** or **`UDP`**. `TCP` is the reliable one, the one that says, “I’m going to make sure this gets there.” `UDP` is more like, “I’m sending it fast, good luck.” For a secure web request like this, `TCP` is in play, and we also see **port `443`**, which tells the destination, “This traffic is for `HTTPS`.”

> From here there is this process called *Encapsulation*: envelope in envelope, that repeats every time we move down the stack
	- It's the process of taking data from one layer and wrapping it with that layer's own information before handing it down to the next layer

3. When the transport layer adds its header, that whole message is now called a segment. Then it gets handed down to layer 3, the **network layer**, where IP addressing lives. This is where the packet gets source and destination IP addresses, basically the full street addresses for where this data came from and where it’s trying to go. Once that layer 3 header is attached, we call it a **packet**.

4. Then we hit layer 2, the data link layer, and now we’re talking **MAC addresses**. These are not the end-to-end addresses like IPs. These are the local-delivery addresses used to get from one device to the next device. At this point, the packet gets wrapped in a ***layer 2 header and trailer***, and now it becomes a *frame*. That frame is what actually gets sent over the physical network.

> **REAL WORLD TIP:** If you ever get confused on an exam or in real life, ask yourself one question: “Am I dealing with end-to-end delivery or local hop-by-hop delivery?” If it’s end-to-end, think IP and layer 3. If it’s local delivery on the current network segment, think MAC address and layer 2.

- So the naming of the data changes like this :
	1. Layer 4 header + data => segment
	2. Layer 3 header + segment => packet
	3. Layer 2 header + layer 2 trailer + packet = frame

5. Now the phase of `De-encapsulation` starts, the switch takes that `Frame` and strips the first encapsulation and sees the destination's MAC Address and sends it to the router, then the router de-encapsulates it (now it's a Packet), then sees the destination and sends it to the switch:
	- Remember, switch operates at Layer 2, it can only see MAC Addresses
	- So the router encapsulates back it's Layer 3 header inside a new layer 2 header : he changes the source and destination's MAC Address

6. Once it reaches the destination it will (de-encapsulates everything) look at the Layer 2 header and checks that it's his MAC Address that's in the Destination, then it de-encapsulates Layer 3, then de-encapsulates Layer 4 : sees TCP/IP 443, then it reaches to the application layer and sees the DATA : browser info, HTTPS etc.
### Youtube Example
- When I watch a YouTube video, the browser starts at the Application layer, where the app requests the content. The Presentation layer makes sure the data is in a usable format and possibly encrypted. The Session layer keeps that communication going. Then the Transport layer chooses whether the traffic should use TCP or UDP, and identifies the service using port numbers.
	- A **port** is just a number that tells a device which service or application should receive the traffic.
- After that, the lower layers take over and actually move the traffic across the network.

> **REAL WORLD TIP:** On the job, don’t make the mistake of treating TCP as “good” and UDP as “bad.” I’ve seen people do that and completely misunderstand application behavior. Voice, video, gaming, and streaming often prefer speed over perfection. File transfers, web pages, logins, and email usually need reliability. The protocol choice should match the business need, not your personal preference.