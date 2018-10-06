import {Injectable} from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {Credentials, Token} from '../shared';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';
import * as jwtDecode from 'jwt-decode';

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

interface AccessToken {
  lastName: string;
  firstName: string;
  mail: string;
  user_name: string;
  displayName: string;
  scope: string[];
  exp: number;
  authorities: string[];
  jti: string;
  client_id: string;
}

const CLIENT_ID = 'internal';

@Injectable({
  providedIn: 'root'
})
export class AuthenticationService {

  constructor(private _http: HttpClient) { }

  getTokenByCredentials(credentials: Credentials): Observable<Token> {
    let formData = new FormData();
    formData.append('grant_type', 'password');
    formData.append('client_id', CLIENT_ID);
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);

    return this._http.post<TokenResponse>('oauth/token', formData).pipe(
      map(AuthenticationService.extractTokenInformation)
    );
  }

  private static extractTokenInformation(tokenResponse: TokenResponse): Token {
    let accessToken = <AccessToken>jwtDecode(tokenResponse.access_token);
    return <Token>{
      tokenType: tokenResponse.token_type,
      accessToken: tokenResponse.access_token,
      refreshToken: tokenResponse.refresh_token,
      expires: new Date(accessToken.exp),

      user: accessToken.user_name,

      displayName: accessToken.displayName,
      lastName: accessToken.lastName,
      firstName: accessToken.firstName,

      mail: accessToken.mail,

      scopes: accessToken.scope,
      authorities: accessToken.authorities
    };
  }
}
