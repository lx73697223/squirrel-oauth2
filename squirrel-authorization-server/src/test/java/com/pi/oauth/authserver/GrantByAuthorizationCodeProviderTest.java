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
import org.junit.Test;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class GrantByAuthorizationCodeProviderTest extends OAuth2Test {

    @Test
    public void getJwtTokenByAuthorizationCode()
            throws IOException, URISyntaxException, InvalidJwtException, JSONException {

        String userName = "app_client";
        String password = "nopass";
        String clientId = "normal-app";
        String clientSecret = "";

        // 1. 请求授权
        String redirectUrl = String.format("%s/resources/user", baseUrl);
        String authorizeByCodeRequestUrl = String.format(
                "%s/oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}",
                baseUrl);
        ResponseEntity<String> response = new TestRestTemplate(userName, password).postForEntity(
                authorizeByCodeRequestUrl, null, String.class, redirectUrl);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        List<String> setCookie = response.getHeaders().get("Set-Cookie");
        String jSessionIdCookie = setCookie.get(0);
        String cookieValue = jSessionIdCookie.split(";")[0];

        // 2. 获取授权码
        String authorizeByCodeUrl = String.format(
                "%s/oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize",
                baseUrl);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookieValue);
        response = new TestRestTemplate(userName, password).postForEntity(authorizeByCodeUrl,
                                                                          new HttpEntity<>(headers),
                                                                          String.class,
                                                                          redirectUrl);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertNull(response.getBody());
        String location = response.getHeaders().get("Location").get(0);
        URI locationURI = new URI(location);
        String query = locationURI.getQuery();

        // 3. 获取 token
        location = String.format(
                "%s/oauth/token?%s&grant_type=authorization_code&client_id=normal-app&redirect_uri={redirectUrl}",
                baseUrl, query);
        response = new TestRestTemplate(clientId, clientSecret).postForEntity(location,
                                                                              new HttpEntity<>(new HttpHeaders()),
                                                                              String.class,
                                                                              redirectUrl);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        HashMap jwtMap = new ObjectMapper().readValue(response.getBody(), HashMap.class);
        String accessToken = (String) jwtMap.get("access_token");
        JwtContext jwtContext = jwtConsumer.process(accessToken);
        logJWTClaims(jwtContext);
        assertEquals(userName, jwtContext.getJwtClaims().getClaimValue("user_name"));

        // 4. 使用 token 请求资源服务

        headers = new HttpHeaders();
        headers.set(GeneralConstants.Authorization_Header,
                    GeneralConstants.Authorization_Token_Prefix + accessToken);

        // 访问不在普通用户角色允许访问的资源
        String getResourceByTokenUrl = String.format("%s/resources/client", baseUrl);
        response = new TestRestTemplate().exchange(getResourceByTokenUrl, HttpMethod.GET,
                                                   new HttpEntity<>(null, headers), String.class);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        // 访问当前角色允许访问的资源
        getResourceByTokenUrl = String.format("%s/resources/user", baseUrl);
        response = new TestRestTemplate().exchange(getResourceByTokenUrl, HttpMethod.GET,
                                                   new HttpEntity<>(null, headers), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());

        // 获取当前角色所有的权限
        getResourceByTokenUrl = String.format("%s/resources/principal", baseUrl);
        response = new TestRestTemplate().exchange(getResourceByTokenUrl, HttpMethod.GET,
                                                   new HttpEntity<>(null, headers), String.class);
        assertEquals(userName, response.getBody());

        //  获取当前用户的角色
        getResourceByTokenUrl = String.format("%s/resources/roles", baseUrl);
        response = new TestRestTemplate().exchange(getResourceByTokenUrl, HttpMethod.GET,
                                                   new HttpEntity<>(null, headers), String.class);
        assertEquals("[{\"authority\":\"ROLE_USER\"}]", response.getBody());
    }

}
