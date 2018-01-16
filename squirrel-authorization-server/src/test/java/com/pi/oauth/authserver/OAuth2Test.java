package com.pi.oauth.authserver;

import com.pi.SquirrelAuthServerApplication;
import com.pi.common.test.FunctionalTests;
import com.pi.common.utils.spring.Profiles;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ActiveProfiles(Profiles.UNIT_TEST)
@SpringBootTest(classes = SquirrelAuthServerApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class OAuth2Test extends FunctionalTests {

    protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

    protected JwtConsumer jwtConsumer;

    protected int port;

    protected String baseUrl;

    @Value("${local.server.port}")
    public void setPort(int port) {
        this.port = port;
        this.baseUrl = String.format("http://localhost:%d", port);
    }

    @Before
    public void setup() {
        jwtConsumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature()
                                              .setSkipSignatureVerification().build();
    }

    protected void logJWTClaims(JwtContext jwtContext) throws JSONException {
        LOGGER.info(prettyPrintJson(JsonUtil.toJson(jwtContext.getJwtClaims().getClaimsMap())));
    }

    protected void logJson(String json) throws JSONException {
        LOGGER.info(prettyPrintJson(json));
    }

    protected String prettyPrintJson(String flatJson) throws JSONException {
        return (new JSONObject(flatJson).toString(3));
    }

}
