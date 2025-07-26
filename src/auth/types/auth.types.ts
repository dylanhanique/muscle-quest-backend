export interface AuthenticatedUser {
  id: number;
  username: string;
}

export interface JwtPayload {
  sub: number; // user id
  username: string;
}

export type CurrentUser = AuthenticatedUser;
