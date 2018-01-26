package com.pi.oauth.resource.config.matcher;

import com.pi.common.utils.constants.GeneralConstants;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class OAuthRequestedMatcher implements RequestMatcher {

    @Override
    public boolean matches(HttpServletRequest request) {
        String auth = request.getHeader(GeneralConstants.AUTHORIZATION_HEADER);
        // Determine if the client request contained an OAuth Authorization
        boolean haveOauth2Token = (auth != null) && auth.startsWith(
                GeneralConstants.AUTHORIZATION_TOKEN_PREFIX);
        boolean haveAccessToken = request.getParameter("access_token") != null;
        return haveOauth2Token || haveAccessToken;
    }

}
