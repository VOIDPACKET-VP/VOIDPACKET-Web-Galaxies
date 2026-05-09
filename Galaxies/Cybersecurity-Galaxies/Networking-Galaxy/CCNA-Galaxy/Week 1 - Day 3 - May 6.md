# Power over Ethernet (PoE)
- Before if you want to deploy IP phone or security camera you always needed 2 things : 
	1. Power (electricity can flow)
	2. Network connectivity (data can flow)
- With `PoE` just one `Ethernet` cable does both

> **REAL WORLD TIP:** When you're planning a PoE deployment, don't just ask, "Does this switch support PoE?" Ask, "How much total PoE budget does this switch have?" I've seen engineers, myself included, plug in a bunch of phones or access points and wonder why the last few won't power up. The switch may support PoE on every port, but not enough wattage for every port at full draw.

## Passive VS active PoE
- Active PoE is polite. Passive PoE kicks the door open and throws electricity into the room.

# Fiber Optic Cables
- Fiber is fast, goes far, and Ignores `EMI` : `Electromagnetic interference` : because it uses light not electricity
- It's also delicate, don't kink it, smash it, bend it ...

> **REAL WORLD TIP:** When you're ordering fiber for a switch uplink or server connection, slow down and check _everything_ first. Connector type, fiber type, distance, and what the device actually supports. Fiber mistakes are annoying because you usually can't just re-terminate it on the fly like copper. Buy the right cable the first time and save yourself a painful trip back to the store.

## Single Mode and Multimode
1. Multimode is usually for shorter distances, often inside a building.
2. Single mode is for long distance runs and high performance links.
3. Both are useful, and you absolutely will see both in the wild.

# I can hack your switches
- **Open Ports are Doorways:** An unused Ethernet jack in a wall or an open port on a switch is an attack surface.
- **Automated Reconnaissance:** Tools like a "Shark Jack" can be plugged into an open port to instantly grab an IP address via DHCP. Once connected, they identify the subnet mask, default gateway, and DNS servers, allowing the attacker to scan the network for vulnerabilities.

## The 3 Layers of Defense

To stop an attacker, you must break the conditions they need to operate (an active port, DHCP access, and network routing).

1. **Administratively Down (The Welded Door):**
    - **Action:** Use the `shutdown` command on any unused ports.
    - **Result:** The port becomes "Administratively Down." Unlike a normal empty port waiting for a connection, this port is intentionally disabled by the admin and will not activate even if a device is plugged in.

2. **The Black Hole VLAN (The Dead End):**
    - **Action:** Assign unused ports to a "Black Hole VLAN."
    - **Result:** A VLAN isolates network traffic. A Black Hole VLAN goes nowhere—it has no DHCP server, no default gateway, and no path to production devices. If an attacker plugs in, they get nothing.
> _Pro-Tip:_ Layer this with "Administratively Down" just in case another admin accidentally turns the port back on.

3. **Port Security & MAC Filtering (The Bouncer):**
    - **The Sneaky Attack:** What if an attacker unplugs a legitimate PC and plugs in their own hacking tool?
    - **Action:** Enable **Port Security** to restrict port access to a specific device's hardware address (MAC address).
    - **Sticky MAC:** Instead of typing MAC addresses manually, the switch learns and "sticks" to the first MAC address it sees on that port.
    - **The Penalty:** If a different MAC address is plugged in later, the switch flags a violation and places the port into an **error-disabled** state (shutting it down automatically).


# Why Packet Tracer Matters
- It's goal is simple : learn Cisco networking without needing physical hardware.

> **REAL WORLD TIP:** In the real world, nobody hires you because you're amazing at clicking around in Packet Tracer. They hire you because you understand how networks work. Packet Tracer is valuable because it gives you a safe place to practice that understanding, make mistakes, break stuff, and try again without taking down a real business network.

