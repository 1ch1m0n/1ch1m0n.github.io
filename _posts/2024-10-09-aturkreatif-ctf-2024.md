---
title: AturKreatif CTF 2024 (SQLi)
description: These challenges was from AturKreatif 2024 CTF by USIM, was glad I had the opportunity to try these challenges myself as a part of my Internship.
categories:
 - Writeup
tags:
- web
- sql
- ctf
---

# 1st Challenge

We were presented with a simple login page. 

![Chal1-1](/assets/images/sqli-practice/chal1-1.png)

So I tried using a simple login bypass payloads from [here](https://github.com/payloadbox/sql-injection-payload-list). Username is `admin'-- ` and for the password just put anything.

![Chal1-2](/assets/images/sqli-practice/chal1-2.png)

Then BOOM! the flag shows.

![Chal1-flag](/assets/images/sqli-practice/chal1-flag.png)
```
Flag: 4turkr34tif24{F1R5T_5T3P_PR0_SQLi}
```
# 2nd Challenge

As for the second challenge, we were presented with a Flight Tracking Express page, user can enter any number to track the flight. Entering apostrophe `'` will show an SQL error.

![Chal2-1](/assets/images/sqli-practice/chal2-1.png)

Firstly we are going enumerate using Union-based SQL Injection. This is to determine the number of columns that we are going to extract information from. After some attempts we identified that there are 7 columns. Payload is `-1' UNION SELECT null, null, null, null, null, null, null-- `

![Chal2-2](/assets/images/sqli-practice/chal2-2.png)


If we look closely at the table, nothing interest us except column **COMPANY**, therefore we can try inserting a place holder to see which column is the COMPANY at. We found out it sits at the third column after using this `-1' UNION SELECT null, null, 'a', null, null, null, null-- ` 

Next, we can use `-1' UNION SELECT null, null, table_name, null, null, null, null FROM information_schema.tables--` to extract the list of all tables. The `information_schema.tables` table,  stores metadata about all tables in the database. The goal here is to extract the names of the tables in the database. 

![Chal2-3](/assets/images/sqli-practice/chal2-3.png)

Here we can see that the query was successful as there were multiple tables that shows up. Scrolling further down, we find something that we are looking for.

![Chal2-4](/assets/images/sqli-practice/chal2-4.png)

There is a table called `fl4g`, we know that we are close. 

We are going to modify the query a little bit, `-1' UNION SELECT null, null, column_name, null, null, null, null FROM information_schema.columns WHERE table_name = 'fl4g'-- `. The goal here is to extract the column names from the fl4g table. 

![Chal2-5](/assets/images/sqli-practice/chal2-5.png)

This will output a column called `f0undM3`. 

![Chal2-6](/assets/images/sqli-practice/chal2-6.png)

Finally, we are going to extract the data in the column `f0undM3` from the `fl4g` table. Modify the payload to `-1' UNION SELECT null, null, f0undM3, null, null, null, null FROM fl4g--`.

![Chal2-7](/assets/images/sqli-practice/chal2-7.png)

Querying turns out successful and the flag will show.

```
Flag: 4turkr34tif24{h4v354f370urn3y}
```

# 3rd Challenge

The third challenges is another login bypass challenge, this time it has little trick. The login will filter out certain characters.

## Level 1

For level 1, it filters `OR`. With a simple `admin'-- ` payload as the username and anything as the password, we will able to bypass it

![Chal3-1](/assets/images/sqli-practice/chal3-1.png)

## Level 2

For level 2, it filters `OR, AND, LIKE, --, =`. We can use something similar but this time using the `#` as a comment. Payload is `admin'# `.

![Chal3-2](/assets/images/sqli-practice/chal3-2.png)

## Level 3

For level 3, it filters `OR, AND, =, >, <, --`. We can use the same payload as Level 2 in order to bypass.

![Chal3-3](/assets/images/sqli-practice/chal3-3.png)

## Level 4

For level 4, it filters `OR, AND, =, >, <, --, UNION, ADMIN`. In order to bypass this we need to use concatenate `|`, the payload is going to be something like `adm'|'in' #`.

![Chal3-4](/assets/images/sqli-practice/chal3-4.png)

After bypassing level 4, the flag is revealed

![Chal3-flag](/assets/images/sqli-practice/chal3-flag.png)

```
Flag: 4turkr34tif24{H4141_1NJ3c710N}
```

# Summary
:P     :/     :O

# Notes
Some useful commands :
- Query for table :-1' UNION SELECT null, null, null, null-- 
- Check version: -1' UNION SELECT null, null, null,@@version--   8.3.0