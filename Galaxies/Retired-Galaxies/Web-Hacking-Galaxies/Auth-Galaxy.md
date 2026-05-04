# Difference 
1. Authentication is :
	- It's who you are : your **identity** .
2. Authorization is :
	- It's what you are **allowed to do** .

# Authentication 
## Brute Forcing 
- Authentication can be bypassed using brute forcing.
- Sometimes our requests can get throttled, so we might wanna use different headers that trick the server into thinking that we are a different user, one of those headers is :
	1. X-Forwarded-For
- There are different ways to go around this :
	2. Sometimes the lock out gets counted per username : so we can use few usernames but with a lot of passwords and start the fuzzing

- Whenever we have multistep login (e.g. MFA, 2FA ...) we start thinking on what edge cases there could be :
	1. Does that token apply to multiple users.
	2. Is the token weak and can be brute forceable.
	3. Does the token expire, can i use it multiple times.
- You can check Alex's checklist for MFA in his website : [Appsecexplained](https://appsecexplained.gitbook.io/appsecexplained/common-vulns/command-injection)

# Authorization (Access Control)

## Types :
1. Vertical access control 
	- Restrict functionalities to some specific users (e.g. Restricting a costumer from editing a product)
 2. Horizontal access control
	 - Restrict access to resources for a specific user (e.g. A user can update there own account but not another user's)
3. Context-Dependent access control
	- It allows or restrict access based on the app's current state (e.g. An app may not allow you to Checkout if there is nothing in your cart) 

## IDOR & BOLA
- It's when the app is returning info based on an object ID.
- When dealing with APIs, we call it ***BOLA***
- The best way to test for this in bug bounty is to make multiple accounts ( A to B testing )
	- So if we see an ID in user A, we would substitute it with the user B's ID.
	- If it works, we can also try stuff like updating accounts etc.

# APIs
- API driven apps behave in a slightly different way, and so we approach them differently.
- The API fetches data, and the data is processed Client-side.

## Autorize
- It's a burp plugin, helps with testing for Broken access control.
- It basically allows you to send requests with a different user's token but as You.
- It shows you either a *BYPASSED* status or a *Enforced* status, we are looking for the Bypassed one of course 
