package com.pi.oauth.authserver;

import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class GrantByImplicitProviderTest extends OAuth2Test {

    @Test
    public void getJwtTokenByImplicitGrant() throws IOException {

        final String UserName = "user";
        final String Password = "password";
        final String ClientId = "normal-app";

        // 1. 请求授权
        String redirectUrl = getBaseUrl() + "/resources/user";
        TestRestTemplate userNameAndPasswordTestRestTemplate = testRestTemplate.withBasicAuth(UserName, Password);
        ResponseEntity<String> response = userNameAndPasswordTestRestTemplate.postForEntity(
                "/oauth/authorize?response_type=token&client_id={client_id}&redirect_uri={redirectUrl}", null,
                String.class, ClientId, redirectUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        List<String> setCookie = response.getHeaders().get("Set-Cookie");
        String jSessionIdCookie = setCookie.get(0);
        String cookieValue = jSessionIdCookie.split(";")[0];

        // 2. 获取授权 token
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookieValue);
        response = userNameAndPasswordTestRestTemplate.postForEntity(
                "/oauth/authorize?response_type=token&client_id={client_id}&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize",
                new HttpEntity<>(headers), String.class, ClientId, redirectUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(response.getBody()).isNull();
        String location = response.getHeaders().get("Location").get(0);

        // FIXME: Is this a bug with redirect URL?
        location = location.replace("#", "?");

        // 3. 使用返回时已经带了 token 参数的 redirectUrl 请求资源服务
        response = testRestTemplate.getForEntity(location, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
