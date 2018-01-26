package com.pi.oauth.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pi.common.utils.constants.GeneralConstants;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.JSONException;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class GrantByClientCredentialTest extends OAuth2Test {

    @Test
    public void getJwtTokenByTrustedClient() throws IOException, JSONException {

        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);

        // 获取 token
        ResponseEntity<String> response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?client_id=trusted-app&grant_type=client_credentials", null, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        String responseText = response.getBody();
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        assertThat(jwtMap.get("token_type")).isEqualTo("bearer");
        assertThat(jwtMap.get("scope")).isEqualTo("read write");
        assertThat(jwtMap.containsKey("access_token")).isTrue();
        assertThat(jwtMap.containsKey("expires_in")).isTrue();
        assertThat(jwtMap.containsKey("jti")).isTrue();

        String accessToken = (String) jwtMap.get("access_token");
        Jwt jwtToken = JwtHelper.decode(accessToken);
        String claims = jwtToken.getClaims();
        LOGGER.info(claims);

        HashMap claimsMap = new ObjectMapper().readValue(claims, HashMap.class);
        assertThat(((List<String>) claimsMap.get("aud")).get(0)).isEqualTo("spring-boot-application");
        assertThat(claimsMap.get("client_id")).isEqualTo(ClientId);
        assertThat(((List<String>) claimsMap.get("scope")).get(0)).isEqualTo("read");
        assertThat(((List<String>) claimsMap.get("scope")).get(1)).isEqualTo("write");

        List<String> authorities = (List<String>) claimsMap.get("authorities");
        assertThat(authorities).hasSize(1);
        assertThat(authorities.get(0)).isEqualTo("ROLE_TRUSTED_CLIENT");
    }

    @Test
    public void accessProtectedResourceByJwtToken() throws IOException, InvalidJwtException, JSONException {

        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        ResponseEntity<String> response = testRestTemplate.getForEntity("/resources/client", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?client_id=trusted-app&grant_type=client_credentials", null, String.class);
        String responseText = response.getBody();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        String accessToken = (String) jwtMap.get("access_token");
        JwtContext jwtContext = jwtConsumer.process(accessToken);
        logJWTClaims(jwtContext);

        HttpHeaders headers = new HttpHeaders();
        headers.set(GeneralConstants.AUTHORIZATION_HEADER, GeneralConstants.AUTHORIZATION_TOKEN_PREFIX + accessToken);

        response = testRestTemplate.exchange("/resources/principal", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo("trusted-app");

        response = testRestTemplate.exchange("/resources/trusted_client", HttpMethod.GET,
                new HttpEntity<>(null, headers), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        response = testRestTemplate.exchange("/resources/roles", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo("[{\"authority\":\"ROLE_TRUSTED_CLIENT\"}]");
    }

}
