# OAuth2.0

1. 授权服务 
   squirrel-authorization-server

2. 资源服务SDK 
   squirrel-resource-server-sdk

## 调用方式

### 授权码模式 (authorization_code)
```
1. 请求授权
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/authorize?response_type=code&client_id={normalClientId}&redirect_uri={redirectUrl}' \
  -H 'Content-Type: Content-Type:application/x-www-form-urlencoded' \
  -H 'Authorization: Basic ${base64({username}:{password},UTF-8)}'

2. 获取授权码
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/authorize?response_type=code&client_id={normalClientId}&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize' \
  -H 'Content-Type: Content-Type:application/x-www-form-urlencoded' \
  -H 'Cookie: JSESSIONID={step1ResponseHeaderJSESSIONID}' \
  -H 'Authorization: Basic ${base64({username}:{password},UTF-8)}'

3. 获取 token
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/token?grant_type=authorization_code&code={step2ResponseHeadersRedirectUrlQueryCode}&client_id={normalClientId}&redirect_uri={redirectUrl}' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Authorization: Basic ${base64({normalClientId}:,UTF-8)}'

4. 使用 token 请求资源服务
curl -X {HttpMethod} \
  'http://{resourceServerHost}:{resourceServerPort}/{uri}' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Authorization:Bearer {token}'
```

### 客户端凭据模式 (client_credentials)
```
1. 获取 token
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/token?grant_type=client_credentials&client_id={trustedClientId}' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Authorization: Basic ${base64({trustedClientId}:{secret},UTF-8)}'

2. 使用 token 请求资源服务
```

### 隐式授权模式 (implicit)
```
1. 请求授权
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/authorize?response_type=token&client_id={normalClientId}&redirect_uri={redirectUrl}' \
  -H 'Content-Type: Content-Type:application/x-www-form-urlencoded' \
  -H 'Authorization: Basic ${base64({username}:{password},UTF-8)}'

2. 获取授权 token
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/authorize?response_type=token&client_id={normalClientId}&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize' \
  -H 'Content-Type: Content-Type:application/x-www-form-urlencoded' \
  -H 'Cookie: JSESSIONID={step1ResponseHeaderJSESSIONID}' \
  -H 'Authorization: Basic ${base64({username}:{password},UTF-8)}'

3. 使用返回时已经带了 token 参数的 redirectUrl 请求资源服务
curl -X GET '${step2ResponseHeadersLocation}'
```

### 资源所有者(即用户)密码类型 (password)
```
1. 获取 token
curl -X POST \
  'http://{authServerHost}:{authServerPort}/oauth/token?grant_type=password&username={username}&password={password}' \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Authorization: Basic ${base64({trustedClientId}:{secret},UTF-8)}'

2. 使用 token 请求资源服务
```

## OAuth2 相关知识点

```
OAuth2 中包含四个角色：
    资源拥有者(Resource Owner)
    资源服务器(Resource Server)
    授权服务器(Authorization Server)
    客户端(Client)

资源服务 N->1 授权服务

授权模式:
    1. authorization_code：授权码类型。
    2. implicit：隐式授权类型。
    3. password：资源所有者(即用户)密码类型。
    4. client_credentials：客户端凭据（客户端ID以及Key）类型。
    5. refresh_token：通过以上授权获得的刷新令牌来获取新的令牌。

OAuth2的运行流程:
+--------+                               +---------------+
|        |--(A)- Authorization Request ->|   Resource    |
|        |                               |     Owner     |
|        |<-(B)-- Authorization Grant ---|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(C)-- Authorization Grant -->| Authorization |
| Client |                               |     Server    |
|        |<-(D)----- Access Token -------|               |
|        |                               +---------------+
|        |
|        |                               +---------------+
|        |--(E)----- Access Token ------>|    Resource   |
|        |                               |     Server    |
|        |<-(F)--- Protected Resource ---|               |
+--------+                               +---------------+



JWT认证协议主体运作流程:
+-----------+                                     +-------------+
|           |       1-Request Authorization       |             |
|           |------------------------------------>|             |
|           |     grant_type&username&password    |             |--+
|           |                                     |Authorization|  | 2-Gen
|           |                                     |Service      |  |   JWT
|           |       3-Response Authorization      |             |<-+
|           |<------------------------------------| Private Key |
|           |    access_token / refresh_token     |             |
|           |    token_type / expire_in           |             |
|  Client   |                                     +-------------+
|           |                                 
|           |                                     +-------------+
|           |       4-Request Resource            |             |
|           |-----------------------------------> |             |
|           | Authorization: bearer Access Token  |             |--+
|           |                                     | Resource    |  | 5-Verify
|           |                                     | Service     |  |  Token
|           |       6-Response Resource           |             |<-+
|           |<----------------------------------- | Public Key  |
+-----------+                                     +-------------+

```
