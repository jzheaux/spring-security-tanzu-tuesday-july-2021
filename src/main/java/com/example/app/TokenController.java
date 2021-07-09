package com.example.app;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/token")
public class TokenController {
	@Autowired
	JwtEncoder encoder;

	@PostMapping
	public String token(Authentication authentication) {
		JoseHeader header = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer("http://resource-server:8080")
				.expiresAt(Instant.now().plusSeconds(3600 * 10))
				.subject(authentication.getName())
				.build();
		Jwt jwt = this.encoder.encode(header, claims);
		return jwt.getTokenValue();
	}
}
