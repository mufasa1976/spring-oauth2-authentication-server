## LDAP
### Initialization
An embedded LDAP-Server provided by unboundid LDAP-SDK will be used.  
This LDAP will be started on ```ldap://localhost:38889/dc=springframework,dc=org``` by  
the ```spring.ldap```-Properties within ```application.yml```:
```
spring:
  ldap:
    embedded:
      base-dn: dc=springframework,dc=org
      port: 33389
```
### LdapUserDetailsService
The OAuth2 ```refresh_token```-Flow needs a ```UserDetailsService``` to refresh the UserDetails from the LDAP-Backend.
Because the Password of the original Bind is not available the original LDAP-Bind can't be used.  
Therefor you have to use a managed LDAP-Bind with ManagerDN and ManagerPassword
```
spring:
  ldap:
    embedded:
      credential:
        username: uid=admin,ou=people,dc=springframework,dc=org
        password: password
```
### Data Load
The embedded LDAP will be initialized by the File ```classpath:/schema.ldif```.  
Because unboundid embedded LDAP-Server needs the base-DN as a separate Node you  
have to put it also into this File (which should not be necessary if you ever used unboundid
embedded LDAP-Server with the Default Spring Security LDAP Configuration because the ```LdapAuthenticationProviderConfigurer```
already adds this base-DN by Default for embedded LDAP-Server).

## RSA Keystore
Create the Keystore:
```
keytool -genkeypair -keystore src/main/resources/jwk.jks -storetype pkcs12 -storepass changeIt -alias jwk -keyalg rsa -keysize 2048
```
## Example Calls

### Password Flow
```
curl -XPOST -H "Content-Type: application/x-www-form-urlencoded" localhost:8080/oauth/token -d "grant_type=password" -d "client_id=my-server-frontend" -d "scope=read write" -d "username=user" -d "password=password"
```

### Refresh-Token Flow
```
curl -XPOST -H "Content-Type: application/x-www-form-urlencoded" localhost:8080/oauth/token -d "grant_type=refresh_token" -d "client_id=my-server-frontend" -d "scope=read write" -d "refresh_token=<refresh-token>"
```

### Client Credentials
Before calling you have to add ```client_credentials``` as an Authorization Type to the ClientDetails:
```
    clients.inMemory()
           .withClient("my-server-frontend")
           .authorizedGrantTypes("authorization_code", "client_credentials", "implicit", "password", "refresh_token");
```
```
curl -u my-server-frontend: localhost:8080/oauth/token -d "grant_type=client_credentials" -d "scope=read write"
```

### Authorization Code Flow
Because the Client ```my-server-frontend``` has been set to autoapprove there will be no Approval Dialog shown.  
Instead the Flow will be directly redirected to the Redirect-URI.
```
curl -u user:password "localhost:8080/oauth/authorize?client_id=my-server-frontend&response_type=code&scope=read%20write&redirect_uri=http://localhost:8080/index.html"
curl -XPOST -H "Content-Type: application/x-www-form-urlencoded" localhost:8080/oauth/token -d "grant_type=authorization_code" -d "client_id=my-server-frontend" -d "scope=read write" -d "code=<Code from Redirect>"
```

### Implicit Flow
```
curl -u user:password "localhost:8080/oauth/authorize?client_id=my-server-frontend&response_type=token&scope=read%20write&redirect_uri=http://localhost:8080/index.html"
```