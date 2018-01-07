# squirrel-authorization-service

* AuthorizationEndpoint：用来作为请求者获得授权的服务，默认的URL是/oauth/authorize.

* TokenEndpoint：用来作为请求者获得令牌（Token）的服务，默认的URL是/oauth/token.

```
配置授权端点的URL:
    POST /oauth/authorize：授权端点。
    POST /oauth/token：令牌端点。
    /oauth/confirm_access：用户确认授权提交端点。
    /oauth/error：授权服务错误信息端点。
    /oauth/check_token：用于资源服务访问的令牌解析端点。
    /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话。
```
