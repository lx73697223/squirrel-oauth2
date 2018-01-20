package com.pi.oauth.authserver;

import com.pi.common.test.FunctionalTests;
import com.pi.common.utils.mapper.json.JsonMapper;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.testng.annotations.BeforeClass;

public abstract class OAuth2Test extends FunctionalTests {

    protected final Logger LOGGER = LoggerFactory.getLogger(getClass());

    @Autowired
    protected JsonMapper jsonMapper;

    protected JwtConsumer jwtConsumer;

    @BeforeClass
    public void setup() {
        jwtConsumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature().setSkipSignatureVerification().build();
    }

    protected void logJWTClaims(JwtContext jwtContext) throws JSONException {
        LOGGER.info(jsonMapper.toJson(jwtContext.getJwtClaims().getClaimsMap()));
    }

}
