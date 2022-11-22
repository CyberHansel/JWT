# JWT
Install JWT Editor extension on Burp  

A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot  
* Header -  base64url-encoded, metadata about the token itself: alg:"HS256" and type:"JWT" and others
* Payload - base64url-encoded,  
* Signature - server that issues the token typically generates the signature by hashing the header and payload. In some cases, they also encrypt the resulting hash. 
    
In practice, JWTs aren't used standalone. The JWT is extended by JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications.   
In other words, a JWT is usually either a JWS or JWE token. When people use "JWT", they almost always mean a JWS token. JWEs are very similar, except that the actual contents of the token are encrypted rather than just encoded.   

According to the JWS specification, only the alg header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.  
* jwk (JSON Web Key) - Provides an embedded JSON object representing the key.  
* jku (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.  
* kid (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching kid parameter.

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
JWT libraries typically provide one method for verifying tokens and another that just decodes them. For example, the Node.js library jsonwebtoken has verify() and decode().
Occasionally, developers confuse these two methods and only pass incoming tokens to the decode() method. This effectively means that the application doesn't verify the signature at all.!  
* Changing JWT "user": value to administrator is possible to connect to restricted /admin panel
## JWT authentication bypass via flawed signature verification  
Among other things, the JWT header contains an alg parameter. This tells the server which algorithm was used to sign the token and, therefore, which algorithm it needs to use when verifying the signature.
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

## JWT authentication bypass via JWK header injection  
The JSON Web Signature (JWS) specification describes an optional jwk header parameter, which servers can use to embed their public key directly within the token itself in JWK format.  
Example:  
> {
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {  
            "kty": "RSA",  
            "e": "AQAB",  
            "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",  
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"  
        }  
     }   
    
Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigured servers sometimes use any key that's embedded in the jwk parameter.
You can exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the jwk header.  
    
 
* In Burp JWT Editor New RSA Key,Generate to automatically generate a new key pair.
* at JWT Change "sub": "administrator", click Attack, then select Embedded JWK, select your newly generated RSA key. In the header of the JWT, observe that a jwk parameter has been added containing your public key.
* Send the request /admin
    
## JWT authentication bypass via JKU header injection  
Instead of embedding public keys directly using the jwk header parameter, some servers let you use the jku (JWK Set URL) header parameter to reference a JWK Set containing the key. When verifying the signature, the server fetches the relevant key from this URL.  
JWK Sets like this are sometimes exposed publicly via a standard endpoint, such as /.well-known/jwks.json.
More secure websites will only fetch keys from trusted domains, but you can sometimes take advantage of URL parsing discrepancies to bypass this kind of filtering. 
    
* In Burp JWT Editor New RSA Key,Generate to automatically generate a new key pair.
* at JWT Change "sub": "administrator"  
* In the browser, go to the exploit server, replace body with {"keys":[]} 
* Back to JWT Editor, right-click on the entry for the key that you just generated, then select Copy Public Key as JWK. and paste in empty [] in exploit server  
* So you we cahnge url in JWT to our malicious exploit server that contains our keys.
    
## JWT authentication bypass via kid header path traversal
Servers may use several cryptographic keys for signing different kinds of data, not just JWTs. For this reason, the header of a JWT may contain a kid (Key ID) parameter, which helps the server identify which key to use when verifying the signature.
Verification keys are often stored as a JWK Set. In this case, the server may simply look for the JWK with the same kid as the token. However, the JWS specification doesn't define a concrete structure for this ID - it's just an arbitrary string of the developer's choosing. For example, they might use the kid parameter to point to a particular entry in a database, or even the name of a file.
If this parameter is also vulnerable to directory traversal, an attacker could potentially force the server to use an arbitrary file from its filesystem as the verification key.  
If the server stores its verification keys in a database, the kid header parameter is also a potential vector for SQL injection attacks.

In this solution, we'll point the kid parameter to the standard file /dev/null and sign the token with a null byte. In practice, you can point the kid parameter to any file with predictable contents.  

* Login, get my account request, change JWT user to administrator, and kid:"../../../../../dev/null"
* Create new WTF symmetric key and change value of k to null byte in Base64 k:"AA=="
* access /admin
    

    
    
    
    
    
    
    
    
    
