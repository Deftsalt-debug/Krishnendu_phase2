# 1. Web gauntlet
Can you beat the filters?

Additional details will be available after launching your challenge instance. (Sites are given after initialising the instance)

Log in as admin http://shape-facility.picoctf.net:50402/ http://shape-facility.picoctf.net:50402/filter.php

## Solution
The website interface along with its cloes give us the idea that we have to utilise some sql injection via the sqlite database. 
Running a default sql payload in the user, we get: 

`SELECT * FROM users WHERE username='admin' --' AND password='lol'`

Here we can ignore the AND password=’lol’ part by making it a comment. -- is one common sql comment that we utilise as a first payload. 
The next round after passing gives us a new flter applied to the user parameter, this is viewed in the second website given to us, the filter.php. Now -- is omitted from our use. I then assume we can simply let the command terminate after the username. Hence the payload is now - `admin';` we get:

`SELECT * FROM users WHERE username='admin'; AND password='haha'`

The same payload works for the next round (as the filer only blocked out /* after round 2, which is another way to make a comment in sql)

Round 4 omits the admin keyword so we then proceed to using the concat operator in sql (after multiple rounds of trial and error)
making the payload look like
`adm'||'in';`

![](IMAGES/weblogin.png "Final webpage after injection")

This same payload works for the next and final round. This yields a final flag under filter.php

![](IMAGES/filterphp.png "Filter website after completion of gauntlet")

## Flag:
```
picoCTF{y0u_m4d3_1t_79a0ddc6}
```

## Concepts learnt
This challenge reqired a further study into sql operators and comments to modify the injection payloads. I've learnt the operators used to make sql comments as well as the concat operator.

## Notes
Here there weren't any incorrect tangents but moreso failed attempts after round 3 as admin was blocked and I struggled to create a tangible payload to break the filter. This had me research a lot more into sqlite and got towards the concat operator.

## Resources
https://www.geeksforgeeks.org/sql/sql-concatenation-operator/
https://www.w3schools.com/sql/sql_comments.asp
https://github.com/payloadbox/sql-injection-payload-list
