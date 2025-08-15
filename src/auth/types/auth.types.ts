export interface AuthenticatedUser {
  id: number;
  username: string;
}

export interface JwtPayload {
  iat: number;
  exp: number;
  sub: number;
  username: string;
}

export type CreateJwtPayload = Pick<JwtPayload, 'sub' | 'username'>;

export type CurrentUser = AuthenticatedUser;
