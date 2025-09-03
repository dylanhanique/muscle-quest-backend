import { RefreshToken } from '../../generated/prisma';
import { PublicUser } from '../../src/user/types/user.types';

export type UserTestFixture = {
  password: string;
  user: PublicUser;
};

export type RefreshTokenTestFixture = {
  refreshToken: string;
  storedRefreshToken: RefreshToken;
};
