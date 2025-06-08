**Time-Based SQL Injection in Blood4life ≤ v1.0 (login.php emailid parameter)**
---
## BUG Author: [Sujal Patel]
---
### Product Information:
---
- Software Link: https://github.com/hackerone889/Blood4life
- BUG Author: Sujal Patel

### Vulnerability Details
---
- Type: Time-Based SQL Injection (CWE-89)
- Affected URL: http://192.168.29.124/blood/bbdms/login.php
- Vulnerable Parameter: Emailid

#### Vulnerable Files:
- File Name: Login.php
- Path: /blood/bbdms/login.php

#### Vulnerability Type
- SQL Injection Vulnerability (CWE-89: SQL Injection)
- Severity: CRITICAL (CVSS v3.1: 9.1)

#### Root Cause
The application directly incorporates unsanitized user input (emailid parameter) into SQL queries without employing parameterized statements or input validation. This improper handling enables attackers to craft time-based SQL injection payloads, leading to unauthorized access or data extraction.

![452726514-0e7d652f-1e2c-4b06-866e-95cfb685c93f](https://github.com/user-attachments/assets/03489186-8456-4148-b285-a70bede55565)


### Impact:
- Unauthorized access to database information  
- Potential exposure of sensitive information (such as user passwords)  
- Possible database corruption or data manipulation

### Description:
---
#### 1. Vulnerability Details:
- In this php code, username parameter is directly concatenated into SQL Statement
- No input validation or escaping mechanisms implemented

#### 2. Attack Vectors:
- Attackers can manipulate SQL query structure using special characters
- Additional information can be extracted using Time Based Payloads
- Database information can be obtained through Time Based injection
- Time based injection might reveal more information

#### 3. Attack Payload Examples: 
```
    Payload: email=' AND (SELECT 5803 FROM (SELECT(SLEEP(5)))LOuf) AND 'Hdtb'='Hdtb&password=Test@123&login=
```

![452726521-02cae346-8e05-4eca-a8bd-fbc5d8b63a91](https://github.com/user-attachments/assets/a7a1d5c4-4b40-4cc1-9ae1-c81e4795be88)


### Proof of Concept:
---
#### Information extraction
```
email=' AND (SELECT 5803 FROM (SELECT(SLEEP(5)))LOuf) AND 'Hdtb'='Hdtb&password=Test@123&login=
```
##### email is injectable!

![3](https://github.com/user-attachments/assets/0218c9d4-f130-401f-b0dd-bbafdd721305)


##### Databases information extracted

![4](https://github.com/user-attachments/assets/2b0708a6-d214-473c-8afa-acce953e58f2)


##### Tables information extracted

![5](https://github.com/user-attachments/assets/b1d62f66-6dce-4e83-a09f-602a49fbed89)

##### Table=tbladmin data dumped!

![6](https://github.com/user-attachments/assets/e9e87543-f56d-4cbe-bb2d-05dc46d7a46b)

### Suggested Remediation:
---
- Implement Prepared Statements
- Input Validation
- Security Recommendations
  - Implement principle of least privilege
  - Encrypt sensitive data storage
  - Implement WAF protection
  - Conduct regular security audits
  - Use ORM frameworks for database operations

### Additional Information:
---
- Refer to OWASP SQL Injection Prevention Guide
- Consider using modern frameworks like MyBatis or Hibernate
- Implement logging and monitoring mechanisms
- References:
 - OWASP SQL Injection Prevention Cheat Sheet
 - CWE-89: SQL Injection
 - CERT Oracle Secure Coding Standard for Java

The severity of this vulnerability is ***HIGH***, and immediate remediation is recommended as it poses a serious threat to the system's data security.

Mitigation Timeline:

- Immediate: Implement prepared statements
- Short-term: Add input validation
- Long-term: Consider migrating to an ORM framework

This vulnerability requires immediate attention due to its potential for significant data breach and system compromise.
