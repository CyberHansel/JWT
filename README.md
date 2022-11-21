# JWT
Install JWT Editor extension on Burp  

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot  
* Header -  base64url-encoded, metadata about the token itself  
* Payload - base64url-encoded,  
* Signature - server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. 
    
In practice, JWTs aren't used standalone. The JWT is extended by JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications.   
In other words, a JWT is usually either a JWS or JWE token. When people use "JWT", they almost always mean a JWS token. JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.   

## JWT authentication bypass via unverified signature  
Implementation flaw is that server doesn't verify the signature of any JWTs that it receives  
Changing JWT "user": value to administrator is possible to connect to restricted /admin panel
## JWT authentication bypass via flawed signature verification  
Change the value of sub claim to administrator
Select the header of the JWT, change the value of the alg parameter to none



