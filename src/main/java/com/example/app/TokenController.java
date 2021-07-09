package com.example.app;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/token")
public class TokenController {
	@Autowired
	JwtEncoder encoder;

	@Autowired
	Map<String, Token> tokens;

	@PostMapping
	public Map<String, String> token(Authentication authentication) {
		Token[] tokens;
		if (authentication instanceof JwtAuthenticationToken) {
			Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
			Token parent = this.tokens.get(jwt.getTokenValue());
			if (!parent.isRefresh()) {
				throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid token");
			}
			parent.revoke();
			tokens = token(authentication.getName());
			Stream.of(tokens).forEach(parent::add);
		} else {
			tokens = token(authentication.getName());
		}

		return Map.of("access_token", tokens[0].getValue(), "refresh_token", tokens[1].getValue());
	}

	private Token[] token(String name) {
		JoseHeader header = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
		JwtClaimsSet claims = defaultClaims(name, 3600 * 10L).build();
		Token accessToken = new Token(false, this.encoder.encode(header, claims).getTokenValue());
		tokens.put(accessToken.getValue(), accessToken);
		claims = defaultClaims(name, 86400 * 30L).build();
		Token refreshToken = new Token(true, this.encoder.encode(header, claims).getTokenValue());
		this.tokens.put(refreshToken.getValue(), refreshToken);
		return new Token[] { accessToken, refreshToken };

	}

	private JwtClaimsSet.Builder defaultClaims(String subject, Long seconds) {
		return JwtClaimsSet.builder()
				.issuer("http://resource-server:8080")
				.expiresAt(Instant.now().plusSeconds(seconds))
				.subject(subject);
	}
}
