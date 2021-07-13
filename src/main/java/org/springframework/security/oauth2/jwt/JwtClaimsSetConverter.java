/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.jwt;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.nimbusds.jwt.JWTClaimsSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link Converter} that converts a {@link JwtClaimsSet} to
 * {@code com.nimbusds.jwt.JWTClaimsSet}.
 *
 * @author Joe Grandja
 * @since 5.5
 * @see Converter
 * @see JwtClaimsSet
 * @see com.nimbusds.jwt.JWTClaimsSet
 */
final class JwtClaimsSetConverter implements Converter<JwtClaimsSet, JWTClaimsSet> {

	@Override
	public JWTClaimsSet convert(JwtClaimsSet claims) {
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// NOTE: The value of the 'iss' claim is a String or URL (StringOrURI).
		Object issuer = claims.getClaim(JwtClaimNames.ISS);
		if (issuer != null) {
			builder.issuer(issuer.toString());
		}

		String subject = claims.getSubject();
		if (StringUtils.hasText(subject)) {
			builder.subject(subject);
		}

		List<String> audience = claims.getAudience();
		if (!CollectionUtils.isEmpty(audience)) {
			builder.audience(audience);
		}

		Instant expiresAt = claims.getExpiresAt();
		if (expiresAt != null) {
			builder.expirationTime(Date.from(expiresAt));
		}

		Instant notBefore = claims.getNotBefore();
		if (notBefore != null) {
			builder.notBeforeTime(Date.from(notBefore));
		}

		Instant issuedAt = claims.getIssuedAt();
		if (issuedAt != null) {
			builder.issueTime(Date.from(issuedAt));
		}

		String jwtId = claims.getId();
		if (StringUtils.hasText(jwtId)) {
			builder.jwtID(jwtId);
		}

		Map<String, Object> customClaims = claims.getClaims().entrySet().stream()
				.filter((claim) -> !JWTClaimsSet.getRegisteredNames().contains(claim.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
		if (!CollectionUtils.isEmpty(customClaims)) {
			customClaims.forEach(builder::claim);
		}

		return builder.build();
	}

}
