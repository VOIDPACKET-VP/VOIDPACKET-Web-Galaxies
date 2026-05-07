# DO NOT Design Your Network Like This!!
- So the idea is : If your network can't survive a pug chewing a cable, or a baby yanking the wrong cord, your design is bad
- So some small businesses who grows fast, needs more ports, more servers more everything. So what people do is add a switch, then another, then another one, and you've got a `Daisy Chain` and it's a problem because : 
	- They have one massive issue => `Single Points of Failure` : if one thing breaks, everything breaks or at least a huge part of the network breaks
- As a network engineer, you're gonna need to spot where they can fail and redesign them

> **REAL WORLD TIP:** When I look at a network diagram, I immediately start asking, "What happens if this link dies? What happens if this switch dies? What happens if this router dies?" If the answer is "half the office goes down," you've found your weak spot. That's how real-world troubleshooting and design starts, not with perfection, but with failure planning.

- So you might think that adding extra links will help: yes, a little, but if the switch itself dies
	- See the issue, so the solution is not redundancy, it's removing dependency on one device being the hero
- So what's the solution, comes the `Two Tier Architecture` 

## Two Tier Architecture
- Here we think in layers : you've got your access layer and your distribution layer
	- `Access layer` : These are the switches your end devices plug into : computers, phones etc.. Their job is to give devices access to the network.
	- Above that we use the `Distribution Layer`, usually built with a `multilayer switch`, also called a `layer 3 switch`
		- It's called `Layer 3 switch` because it handles both `MAC Address switching` and `IP routing` 
		- This `Distribution Switch` becomes the boss : Devices talk up to it, across through it, and out through it. It handles things like routing between VLANs, which are just separate logical networks on the same physical hardware, and it does it fast. 
- Now one distribution switch is better than a daisy chain, _but it's still a possible failure point._ So the better version is two distribution switches, but Redundancy is expensive, you can design the best network, but if the company can't pay for it, it's not happening 
	- So network design is nit just technical, it's also business, you balance risk and cost, you ask yourself : what can we afford to lose? etc.
![[Screenshot 2026-05-06 182816.png]]

> A network that "works most of the time" can still be a terrible design. In business, "most of the time" often means "until the exact moment we can't afford downtime (Servers going down, software updates, or network outages...)."

## When Two Tiers Aren't Enough
- When a small business grows beyond one building and becomes more of a campus, multiple buildings, lots of users...We need something more powerful than `Two Tiers`, comes the `three-tier architecture` 
- To make it work we add another layer above the distribution layer called : `Core Layer`
	- The access layer connects devices.
	- The distribution layer aggregates and routes locally.
	- The core layer becomes the fast, reliable backbone tying the campus together
![[Screenshot 2026-05-06 183032.png]]

> the two-tier model is often called a collapsed core design, That's because the distribution layer is doing double duty. It's not just handling distribution tasks, it's also acting as the backbone for the network. And sometimes that's all your business needs

> When designing you need to think about matching architecture to business size, traffic demands, and budget.

# Data Center Networks
- At the beginning they were designed like office networks, but it turned to be a problem, so in this Chapter we'll learn why they had to evolve into something very different
- Almost everything you touch online lives in one of these places somewhere, that could be in our little server room, or the cloud

> **REAL WORLD TIP:** On the job, a lot of companies live in a **hybrid** world. They might have some gear on premises, some equipment in a rented data center, and some services in AWS or Azure.

- Now let's talk about that old design: they're built using `Three-tier design`, at the rack you'd put `Top-of-rack switches` (`ToR switches`) : they're connected to the a distribution layer, and that connects up to a core layer
	- Which made sense back then when traffic came from the outside world to the server and came back out, this type of traffic is called : `North-South Traffic`
	- But now servers started talking to other servers all over the data center, it began communicating sideways also known as `East-West Traffic` 
- So now the main event was `East-West Traffic` in networks built for `North-South Traffic` : hhhhh see the problem
## The solution : spine-leaf design
- So We still have switches at the rack level connecting to servers, but now we call those **leaf switches**. Above them we place **spine switches**, and every leaf switch connects to every spine switch.
- So before if a server wanted to talk to another server a lot of hops need to be done, now Any server connected to any leaf can reach any server connected to any other leaf in a maximum of two hops.
	- Leaf to Spine, Spine to Leaf
	- It's fast, predictable
- Links between Leaf and Spine are `Layer 3` connections : we're routing between them using IP, so now we can keep those uplinks Active and not rely on Spanning tree

> modern data centers are built to optimize east-west traffic, not just user-to-server traffic. And that's why spine-leaf became the standard.

# WAN (Wide Area Network)
- People think it's the internet, but that's not always the case, but it's just the stuff that connects your separate locations across distance
	- Connecting the office to data center etc.
- When talking about one contained location, that's `LAN (Local Area Network)`

> A WAN isn't just about connecting places. It's about connecting business functions that happen to live in different places.

## MPLS : Multiprotocol Label Switching
- It's not the public internet. It is a provider-managed private WAN service. Often called private and secure
- How it works : 
	- I call the provider and say, "I want all my sites connected privately," and they say, "Cool, plug into our network and we'll handle the magic in the middle."
- MPLS is a `Layer 2.5` technology : sits between normal data link behavior and normal Layer 3 routing behavior.

> Something to remember if you're heading the Cisco path : CE router (customer edge) and PE router (provider edge)

## Metro Ethernet
- It's Fast, low latency, it's `layer 2`.
- How it works :
	- "Hey provider, I want a blazing fast connection between these two sites in the same metro area." And they give you one. Often Fiber, often used between corporate office and data center or between 2 data centers
- Types :
	1. E-Line: point-to-point
	2. E-LAN: multipoint
	3. E-Tree: hub-and-spoke

> **REAL WORLD TIP:** If you're trying to decide between MPLS and Metro Ethernet, start with the business need, not the technology label. If the goal is high-speed connectivity between major sites like corporate and a data center, Metro Ethernet often makes a ton of sense. If the goal is connecting many branches privately through a carrier, MPLS has historically been the better fit.

## When WAN is the internet
- So instead of paying for private carrier WAN services, you pay for regular business internet connections and build a `site to site VPN` : traffic is encrypted between locations as it crosses the wild internet
- It's cheaper but it's unpredictable, jittery..., the traffic will be treated rudely
- Comes the `SD-WAN` : allows intelligent use of regular internet connections, improves path selection, performance and cloud access where most of our data center live

> So as a recap for WAN : it means the connectivity between our separate locations. Sometimes that is private carrier infrastructure like leased lines, MPLS, or Metro Ethernet. Sometimes it's the public internet with VPNs on top. The right answer depends on cost, performance, geography, and what our business actually needs

# Let's hack your home network
- Most home networks are what we call `SOHO Network` : a setup where one device does everything
- So you always want to ask yourself these questions:
	- can someone attack you from the internet?
	- can one of your internal devices become the weak link?
	- is your wireless network easy to abuse?
	- how are you connecting back to your company if you're working from home?
- The first is the most obvious, the ISP gives your router a `Public IP Address` : that's what the internet sees, it's how traffic finds its way back to your network.
	- If someone knows that address, they can prob it, check for open ports (`nmap`), look for vulns to exploit
	- You can test this yourself BTW

> **REAL WORLD TIP:** If you're testing your public IP from the outside, do it from a cloud server or another network, not from inside your own LAN. You want to see what the internet sees. And if you find open ports you don't recognize, don't "investigate later." Close them now, then figure out what broke afterward.

## Upgrade the router you have
- You don't need to buy new gear now, but we can make our router lot safer, not perfect but better
	- Check the Firewall is enabled
	- Turn off port forwarding unless you absolutely know why it's there
	- Disable **remote management** : let's people try to log in to your router from the internet
	- change the default admin username and password
	- update the **firmware** : router's OS
	- If wireless : Use WPA2 at minimum, or WPA3 if your gear supports it.
		- Change the default **SSID** : wireless network name
	- Disable `ping` : If your router has an option to stop responding to WAN pings, disable it.
	- `IoT` devices are also a pain in the *** , so use `Segmentation` : 
		- Trusted devices in one network, IoTs on another, Put guest devices on another
	- If your gear supports **VLANs** (`virtual network separations`) use them
	- It it supports client isolation use it
- If your gear isn't enough, then it's time for an upgrade, you'll get access to :
	- better firewall policies, VLAN support, traffic visibility, VPN options, and in some cases **IDS/IPS**. That's Intrusion Detection System and Intrusion Prevention System, which means your network can actually inspect traffic for known threats and sometimes block them automatically.
- Use a VPN (`Virtual Private Network`) if you work from home
	- It works by creating an encrypted tunnel between you and the destination network (your company)

# Hybrid Cloud
- The idea is knowing what belongs in the cloud what belongs in your own data center (on-prem), and how to make those 2 worlds work together
## On-prem vs Cloud
- The upside of `On-prem` is control, your hardware, your rules etc. the Downside is price
- Cloud: you rent someone else's infrastructure, and stop when you don't need them, so it's flexible and cheaper

> Remember what we said in the beginning, it's about pairing the technical problem with the right home

# Ethernet Cables
- So if you're working towards CCNA, knowing how to make one, and understanding what's happening inside matters
- WHY ? in the real world You're making them because you need a custom length, or because a cable run got damaged
- So what do you need :
	- Ethernet Cable : Cat5e UTP
	- RJ45 connector
	- Crimping tool
	- Cable tester

> **REAL WORLD TIP:** In the job world, I almost always prefer buying pre-made patch cables when I can. They’re cleaner, more reliable, and save time. But when you’re doing structured cabling through walls or ceilings, you absolutely need to know how to terminate your own ends, and you definitely want a cable tester nearby to save yourself from insane troubleshooting later.

- We start with stripping the sheath : outer jacket of the cable
	- Don't nick the copper inside, you'll face a big problem

## What's inside it
- You'll find 4 twisted pairs : 8 copper wires, they're twisted because it helps fight 2 things :
	1. **Electromagnetic** **interference** (EMI)
	2. Crosstalk
- It's why they're called `UTP` unshielded twisted pairs. In places where there is a ton of electrical noise, you might use `STP` shielded twisted pairs

## Straight through VS Crossover
- Devices like PCs used to send traffic on specific pins and receive on others, Switches were designed to complement that, That's why a straight-through cable worked when connecting a PC to a switch.
	- One side talks, the other listens
- But when you connect a PC to a PC or Switch to Switch, they were both talking on the same pins and listening on the same pins. Nobody was hearing anybody. 
- That’s where a `crossover cable` came in, swapping the transmit and receive pairs so the conversation could actually happen.

> NOTE : With modern gigabit Ethernet, devices commonly support **Auto-MDIX**, which is basically smart enough to figure all that out automatically and adjust the pins for you.
> So Crossover cables don't matter as much now

## The Pinout You need to know
- When it's time to build the cable, you can use the `T568B` standard : the common pinout for straight-through cables. NOTE > You'll need to memorize the order of wire colors :
	1. White orange
	2. Orange
	3. White green
	4. Blue
	5. White blue
	6. Green
	7. White brown
	8. Brown

## The Other steps of the process
1. Untwist the pairs
2. straighten the wires 
3. arrange them in the correct order 
4. trim them evenly
5. slide them into the RJ45 connector with the clip facing down, and crimp. 
6. Then do the exact same thing on the other end for a straight-through cable.
7. Test it using a cable tester : If the tester lights up pins 1 through 8 in order on both ends, you did it!

> Standard copper Ethernet runs top out at 100 meters. Go longer than that, and your signal starts degrading.