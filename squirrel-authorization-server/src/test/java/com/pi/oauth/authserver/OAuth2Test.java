package com.pi.oauth.authserver;

import com.pi.SquirrelAuthServerApplication;
import com.pi.common.utils.spring.Profiles;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ActiveProfiles(Profiles.UNIT_TEST)
@SpringBootTest(classes = SquirrelAuthServerApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class OAuth2Test {

    protected static final Logger logger = LoggerFactory.getLogger(OAuth2Test.class);

    protected JwtConsumer jwtConsumer;

    @Before
    public void setup() {
        jwtConsumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature()
                                              .setSkipSignatureVerification().build();
    }

    protected void logJWTClaims(JwtContext jwtContext) throws JSONException {
        logger.info(prettyPrintJson(JsonUtil.toJson(jwtContext.getJwtClaims().getClaimsMap())));
    }

    protected void logJson(String json) throws JSONException {
        logger.info(prettyPrintJson(json));
    }

    protected String prettyPrintJson(String flatJson) throws JSONException {
        return (new JSONObject(flatJson).toString(3));
    }

}
