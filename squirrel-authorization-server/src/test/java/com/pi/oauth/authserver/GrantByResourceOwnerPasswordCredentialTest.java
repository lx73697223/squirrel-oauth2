package com.pi.oauth.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pi.common.utils.constants.GeneralConstants;
import org.jose4j.jwt.consumer.InvalidJwtException;
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

public class GrantByResourceOwnerPasswordCredentialTest extends OAuth2Test {

    @Test
    public void getJwtTokenByClientCredentialForUser() throws IOException {

        final String UserName = "user";
        final String Password = "password";
        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        ResponseEntity<String> response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?grant_type=password&username={username}&password={password}", null, String.class,
                UserName, Password);
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
        assertThat(claimsMap.get("user_name")).isEqualTo(UserName);
        assertThat(((List<String>) claimsMap.get("scope")).get(0)).isEqualTo("read");
        assertThat(((List<String>) claimsMap.get("scope")).get(1)).isEqualTo("write");

        List<String> authorities = (List<String>) claimsMap.get("authorities");
        assertThat(authorities).hasSize(1);
        assertThat(authorities.get(0)).isEqualTo("ROLE_USER");
    }

    @Test
    public void getJwtTokenByClientCredentialForAdmin() throws IOException {

        final String UserName = "admin";
        final String Password = "password";
        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        ResponseEntity<String> response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?grant_type=password&username={username}&password={password}", null, String.class,
                UserName, Password);
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
        assertThat(claimsMap.get("user_name")).isEqualTo(UserName);
        assertThat(((List<String>) claimsMap.get("scope")).get(0)).isEqualTo("read");
        assertThat(((List<String>) claimsMap.get("scope")).get(1)).isEqualTo("write");
        assertThat(((List<String>) claimsMap.get("authorities")).get(0)).isEqualTo("ROLE_ADMIN");
    }

    @Test
    public void accessProtectedResourceByJwtTokenForUser() throws IOException, InvalidJwtException, JSONException {

        final String UserName = "user";
        final String Password = "password";
        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        ResponseEntity<String> response = testRestTemplate.getForEntity("/resources/user", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?grant_type=password&username={username}&password={password}", null, String.class,
                UserName, Password);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        String responseText = response.getBody();
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        String accessToken = (String) jwtMap.get("access_token");

        HttpHeaders headers = new HttpHeaders();
        headers.set(GeneralConstants.Authorization_Header, GeneralConstants.Authorization_Token_Prefix + accessToken);

        response = testRestTemplate.exchange("/resources/user", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        response = testRestTemplate.exchange("/resources/principal", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo(UserName);

        response = testRestTemplate.exchange("/resources/roles", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo("[{\"authority\":\"ROLE_USER\"}]");
    }

    @Test
    public void accessProtectedResourceByJwtTokenForAdmin() throws IOException {

        final String UserName = "admin";
        final String Password = "password";
        final String ClientId = "trusted-app";
        final String ClientSecret = "secret";

        ResponseEntity<String> response = testRestTemplate.getForEntity("/resources/admin", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        response = clientAndSecretTestRestTemplate.postForEntity(
                "/oauth/token?grant_type=password&username={username}&password={password}", null, String.class,
                UserName, Password);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        String responseText = response.getBody();
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        String accessToken = (String) jwtMap.get("access_token");

        HttpHeaders headers = new HttpHeaders();
        headers.set(GeneralConstants.Authorization_Header, GeneralConstants.Authorization_Token_Prefix + accessToken);

        response = testRestTemplate.exchange("/resources/admin", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        response = testRestTemplate.exchange("/resources/principal", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo(UserName);

        response = testRestTemplate.exchange("/resources/roles", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo("[{\"authority\":\"ROLE_ADMIN\"}]");
    }

}
