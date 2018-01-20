/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.pi.oauth.authserver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pi.common.utils.constants.GeneralConstants;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.JSONException;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class GrantByAuthorizationCodeProviderTest extends OAuth2Test {

    @Test
    public void getJwtTokenByAuthorizationCode()
            throws IOException, URISyntaxException, InvalidJwtException, JSONException {

        final String UserName = "app_client";
        final String Password = "nopass";
        final String ClientId = "normal-app";
        final String ClientSecret = "";

        // 1. 请求授权
        TestRestTemplate userNameAndPasswordTestRestTemplate = testRestTemplate.withBasicAuth(UserName, Password);
        String redirectUrl = getBaseUrl() + "/resources/user";
        ResponseEntity<String> response = userNameAndPasswordTestRestTemplate.postForEntity(
                 "/oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}",
                null, String.class, redirectUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        List<String> setCookie = response.getHeaders().get("Set-Cookie");
        String jSessionIdCookie = setCookie.get(0);
        String cookieValue = jSessionIdCookie.split(";")[0];

        // 2. 获取授权码
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookieValue);
        response = userNameAndPasswordTestRestTemplate.postForEntity(
                "/oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize",
                new HttpEntity<>(headers), String.class, redirectUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String location = response.getHeaders().get("Location").get(0);
        URI locationURI = new URI(location);
        String query = locationURI.getQuery();

        // 3. 获取 token
        TestRestTemplate clientAndSecretTestRestTemplate = testRestTemplate.withBasicAuth(ClientId, ClientSecret);
        location = String.format(
                "/oauth/token?%s&grant_type=authorization_code&client_id=normal-app&redirect_uri={redirectUrl}", query);
        response = clientAndSecretTestRestTemplate.postForEntity(location, new HttpEntity<>(new HttpHeaders()),
                String.class, redirectUrl);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        HashMap jwtMap = new ObjectMapper().readValue(response.getBody(), HashMap.class);
        String accessToken = (String) jwtMap.get("access_token");
        JwtContext jwtContext = jwtConsumer.process(accessToken);
        logJWTClaims(jwtContext);
        assertThat(UserName).isEqualTo(jwtContext.getJwtClaims().getClaimValue("user_name"));

        // 4. 使用 token 请求资源服务

        headers = new HttpHeaders();
        headers.set(GeneralConstants.Authorization_Header, GeneralConstants.Authorization_Token_Prefix + accessToken);

        // 访问不在普通用户角色允许访问的资源
        response = testRestTemplate.exchange("/resources/client", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // 访问当前角色允许访问的资源
        response = testRestTemplate.exchange("/resources/user", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);

        // 获取当前角色所有的权限
        response = testRestTemplate.exchange("/resources/principal", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo(UserName);

        //  获取当前用户的角色
        response = testRestTemplate.exchange("/resources/roles", HttpMethod.GET, new HttpEntity<>(null, headers),
                String.class);
        assertThat(response.getBody()).isEqualTo("[{\"authority\":\"ROLE_USER\"}]");
    }

}
