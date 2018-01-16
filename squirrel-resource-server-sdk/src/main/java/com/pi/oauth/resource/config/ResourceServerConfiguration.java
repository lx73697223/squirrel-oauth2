package com.pi.oauth.resource.config;

import com.pi.common.utils.core.IteratorUtils;
import com.pi.oauth.resource.config.matcher.OAuthRequestedMatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

import java.util.List;

@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Value("${oauth2.resource-id}")
    private String resourceId;

    @Value("'${oauth2.resource-exclude-paths}'.split(',')")
    private List<String> excludePaths;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(resourceId);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.requestMatcher(new OAuthRequestedMatcher())
            .authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll()
            .anyRequest().authenticated();

        if (IteratorUtils.isNotEmpty(excludePaths)) {
            String[] paths = new String[excludePaths.size()];
            http.authorizeRequests().antMatchers(excludePaths.toArray(paths)).permitAll()
                .anyRequest().authenticated();
        }
        // @formatter:on
    }

}
