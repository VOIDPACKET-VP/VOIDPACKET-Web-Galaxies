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
	- If it’s remote, it uses `ARP` to discover the router’s MAC address, because the router is the next stop.

> **REAL WORLD TIP:** When a device can reach local machines but not the internet, one of the first things I check is the default gateway. Wrong gateway, missing gateway, or a gateway that’s down will break off-network communication fast. You’ll look like a wizard for spotting it early, but really you’re just understanding how routing actually works.

## Behind the scenes of the router
