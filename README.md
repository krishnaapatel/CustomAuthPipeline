# Liferay custom auth pipeline

Liferay provides JSON remote service and we can access it from outside of the portal. 
There is also a concept of private remote API and for that Liferay 6.x provide Basic Authentication by default. But As we know Basic Authentication use username and password and it is easily decodable. So, we can use any alternative for authentication. I have use JWT (JSON Web Token).

## Implementation

You need to apply custom AuthVerifier. So, Liferay will go through that verifier before any authentication. You can customize any Liferay functionality by Hook.

JWT implementation need some dependencies([refer](https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt/0.2))


## Usage

you can create and decode JWT token using its library. like,

```java
//generate token by jwt builder
token  = Jwts.builder()
        .setSubject(subject)
        .setClaims(claims)					 
        .setExpiration(c.getTime())					 
        .signWith(signatureAlgorithm,signingKey)
        .compact();

//decode token by parser
Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary("abcdef12345abcdef12345abcdef12345abcdef12345"))
               .parseClaimsJws(token).getBody();
```
now, You will have your own token while you get API request from client. You can user that encrypted data from token to verify user. 

```java
String[] tokenData = new TokenDecoder().decodeJWToken(token);
//You will get decoded data from token and you can verify with your data.
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

