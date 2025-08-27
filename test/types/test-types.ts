import { RefreshToken } from '../../generated/prisma';
import { PublicUser } from '../../src/users/types/user.types';

export type UserTestFixture = {
  password: string;
  storedUser: PublicUser;
};

export type RefreshTokenTestFixture = {
  refreshToken: string;
  storedRefreshToken: RefreshToken;
};
