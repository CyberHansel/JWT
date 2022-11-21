# JWT
Install JWT Editor extension on Burp  

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot  
* Header -  base64url-encoded, metadata about the token itself  
* Payload - base64url-encoded,  
* Signature - server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. 
    
In practice, JWTs aren't used standalone. The JWT is extended by JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications.   
In other words, a JWT is usually either a JWS or JWE token. When people use "JWT", they almost always mean a JWS token. JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.   

=======================

Alghorithms

Signatures are not encryption, signatures only allow verification that the content of the JWT was not changed. RS256 and HS256 are the most common algorithms used for signing JWTs. RS256 (RSA using SHA256) and HS256 (HMAC using SHA256) are the most common algorithms used for signing JWTs, also there is ES256 or PS256.

Signatures are created by combining encoded versions of the header and payload of a JWT, passing them and the secret as parameters into the algorithm defined in the header. example code that can be used to create a JWT signature:

HMACSHA256(  
    base64UrlEncode(header) + "." +  
    base64UrlEncode(payload),  
    secret)    
Example output of what the signed JWT looks like:  
> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c    

HS256 (HMAC with SHA-256) is a symmetric keyed hashing algorithm that uses one secret key. Symmetric means two parties share the secret key. The key is used for both generating the signature and validating it.  
Be mindful when using a shared key; it can open potential vulnerabilities if the verifiers(multiple applications) are not appropriately secured.  

RS256 (RSA Signature with SHA-256) is an asymmetric algorithm that uses a public/private key pair. The identity provider has a private key to generate the signature. The receiver of the JWT uses a public key to validate the JWT signature. The public key used to verify and the private key used to sign the token are linked since they are generated as a pair. 

You might be wondering if there is any scenario where you would choose HS256? And yes, there are a couple of situations where you may use HS256.
You could consider using HS256 when working on legacy applications that can't support RS256. Another possible use case for using HS256 instead of RS256 is when your application makes a very large number of requests because HS256 is more efficient than RS256.

=======================

## JWT authentication bypass via unverified signature  
Server doesn't verify the signature of any JWTs that it receives allows to accept all JWT!
Changing JWT "user": value to administrator is possible to connect to restricted /admin panel
## JWT authentication bypass via flawed signature verification  
Server allows to delete signature and accepts none alg

* Change "alg": "none"
* Change "sub": "administrator"  
* delete signature part, cos we changes value to none, but leave second .
* GET /admin/delete?username=carlos HTTP/1.1  
## JWT authentication bypass via weak signing key  
Server has weak JWT signature that can be hacked with hashcat
* Copy JWT and brute-force the secret:  
* hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list --show         #secret1 example secret
* In Burp, JWT Editor Keys tab click New Symmetric Key, Generate and replace k parameter with secret1  
* Replace k value with the Base64-encoded secret1.  
* at JWT Change "sub": "administrator" and at bottom click Sign (Don't modify header option) 
Token is now modified and signed. With token we access to administrator acc.

## JWT authentication bypass via jwk header injection  

!(JWKS) is a set of keys containing the public keys used to verify any JSON Web Token (JWT) issued by the Authorization Server and signed using the RS256 signing algorithm  
This lab uses a JWT-based mechanism for handling sessions. The server supports the jwk parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.  
    
* In Burp JWT Editor New RSA Key,Generate to automatically generate a new key pair.
* at JWT Change "sub": "administrator", click Attack, then select Embedded JWK, select your newly generated RSA key. In the header of the JWT, observe that a jwk parameter has been added containing your public key.
* Send the request /admin
    
## JWT authentication bypass via weak signing key


    
    
    
    
    
    
    
    
    
