package com.example.app;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

	@Value("${jwt.public.key}")
	RSAPublicKey pub;

	@Value("${jwt.private.key}")
	RSAPrivateKey priv;

	@Bean
	@Order(1)
	SecurityFilterChain tokenEndpoint(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.requestMatchers((requests) -> requests.mvcMatchers("/token"))
				.authorizeRequests((authz) -> authz.anyRequest().authenticated())
				.httpBasic(Customizer.withDefaults())
				.csrf((csrf) -> csrf.ignoringAntMatchers("/token"));
		// @formatter:on
		return http.build();
	}

	@Bean
	JwtEncoder jwtEncoder() {
		RSAKey key = new RSAKey.Builder(this.pub)
				.privateKey(this.priv)
				.build();
		return new NimbusJwsEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
	}

	@Bean
	@Order(2)
	SecurityFilterChain appEndpoints(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authz) -> authz.anyRequest().authenticated())
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
		return http.build();
		// @formatter:on
	}

	@Bean
	JwtDecoder jwtDecoder() {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(this.pub).build();
		OAuth2TokenValidator<Jwt> defaults = JwtValidators.createDefaultWithIssuer("http://resource-server:8080");
		decoder.setJwtValidator(defaults);
		return decoder;
	}

	@Bean
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.authorities("app")
						.build()
		);
	}

}
