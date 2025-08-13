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

export interface RefreshTokenPayload {
  id: string;
  sub: number;
  iat: number;
  exp: number;
}

export type CurrentUser = AuthenticatedUser;
