## Example Calls

### Password Flow
```
curl -u my-server-frontend:s3cr3t localhost:8080/oauth/token -d "grant_type=password" -d "scope=read write" -d "username=user" -d "password=password"
```

### Refresh-Token Flow
```
curl -u my-server-frontent:s3cr3t localhost:8080/oauth/token -d "grant_type=refresh_token" -d "scope=read write" -d "refresh_token=<refresh-token>"
```

### Client Credentials
```
curl -u my-server-frontend:s3cr3t localhost:8080/oauth/token -d "grant_type=client_credentials" -d "scope=read write"
```

### Authorization Code with Response-Type Token (without Client Secret)
```
curl -u user:password "localhost:8080/oauth/authorize?grant_type=authorization_code&client_id=my-server-frontend&response_type=token&scope=read%20write&redirect_uri=http://localhost:8080/index.html"
```

### Authorization Code with Response-Type Code (without Client Secret)
```
curl -u user:password "localhost:8080/oauth/authorize?grant_type=authorization_code&client_id=my-server-frontend&response_type=code&scope=read%20write&redirect_uri=http://localhost:8080/index.html"
```