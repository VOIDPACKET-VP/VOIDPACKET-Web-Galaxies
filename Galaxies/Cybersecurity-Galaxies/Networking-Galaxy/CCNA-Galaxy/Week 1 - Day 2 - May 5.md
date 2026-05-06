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

# WAN
