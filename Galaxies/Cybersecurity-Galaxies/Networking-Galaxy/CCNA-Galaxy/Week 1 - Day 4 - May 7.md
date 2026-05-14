- Here we start learning on how to setup a network in packet tracer

> Remember a network can be as simple as 2 devices talking

- We can summarize everything in this :
	- Open packet tracer
	- Bring some devices and a switch
	- connect them using cables
	- Decide on a main Ip for that network 
		- e.g. `192.168.1.0/24`
	- set their IP addresses 
		- Click on the device > `config` > `fastethernet0` > Then set the IPv4 and hit tab to auto complete the subnet mask : that `/24`
		- e.g. `192.168.1.1` and subnet will be `255.255.255.0` if we used `/24` 
	- For the switch you have to :
		- click on the device > CLI > type these commands one at a time :
			1. `enable`
			2. `configure terminal`
			3. `interface vlan 1`
			4. `ip address` `<ip>` `<subnet>` 
			5. `no shutdown`


> **REAL WORLD TIP:** In the real world, clear diagrams beat pretty diagrams almost every time. If another tech can quickly look at your topology and understand device names, interfaces, and IP addresses, you've won. Don't burn an extra hour trying to make Packet Tracer look like an architectural rendering when five minutes of notes and labels would make it more useful.


- There are 2 modes in packet tracer : 
![[Screenshot (129).png]]
	1. Realtime : allows you to see things happen like real life : when you `ping` an IP in the command prompt of a device you see those responses like you would usually do
	2. Simulation : Allows you to see what happens behind the scenes so that you get back those `ping` responses 