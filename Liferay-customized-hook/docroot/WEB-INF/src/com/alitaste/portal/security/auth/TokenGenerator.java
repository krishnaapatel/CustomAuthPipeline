package com.alitaste.portal.security.auth;


import java.security.Key;
import java.util.Calendar;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import com.liferay.portal.kernel.util.PropsUtil;
import com.liferay.portal.kernel.util.Validator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenGenerator {
	
	public String getJWToken(long userId, long facebookId, String subject, String email, String password) {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		String token = null;
		try{
			byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary("abcdef12345abcdef12345abcdef12345abcdef12345");
			Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
			Calendar c = Calendar.getInstance();
			c.add(Calendar.MONTH, 1);
			Claims claims = Jwts.claims().setSubject("POL");
			claims.put("userId", userId);
			claims.put("password", password);
			claims.put("facebookId", facebookId);
			claims.put("email", email);
			token  = Jwts.builder()
					.setSubject(subject)
					.setClaims(claims)
					.setExpiration(c.getTime())
					.signWith(signatureAlgorithm,signingKey)
					.compact();
		}catch(Exception e){
		}
		return token;
	}

	public String[] decodeJWToken(String token) {
		String[] tokenData = null;
		try{
			if(Validator.isNotNull(token) && !token.equals("undefined")) {
				Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary("abcdef12345abcdef12345abcdef12345abcdef12345"))
						.parseClaimsJws(token).getBody();
				tokenData = new String[4];
				
				tokenData[3] = String.valueOf(claims.get("facebookId"));
				tokenData[2] = String.valueOf(claims.get("password"));
				tokenData[1] = String.valueOf(claims.get("email"));
				tokenData[0] = String.valueOf(claims.get("userId"));
			}				
		} catch (Exception e) {
		}		
		return tokenData;
	}
	
}
