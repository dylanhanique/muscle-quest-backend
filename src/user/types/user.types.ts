export interface User {
  id: number;
  username: string;
  email: string;
  password: string;
  createdAt: Date;
  updatedAt?: Date;
}

export type UserCredentials = Pick<User, 'id' | 'username' | 'password'>;
export type PublicUser = Omit<User, 'password' | 'createdAt' | 'updatedAt'>;
