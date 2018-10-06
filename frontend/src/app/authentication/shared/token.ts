export interface Token {
  tokenType: string;
  accessToken: string;
  refreshToken: string;
  expires: Date;

  user: string;

  displayName: string;
  lastName: string;
  firstName: string;

  mail: string;

  scopes: string[];
  authorities: string[];
}
