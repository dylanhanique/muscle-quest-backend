import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { UsersService } from '../../users/users.service';
import { LoginDto } from '../dto/auth.dto';
import { faker } from '@faker-js/faker';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { UserCredentials } from 'src/users/types/user.types';
import { AuthenticatedUser, CreateJwtPayload } from '../types/auth.types';
import { getEnvVar } from '../../common/functions';
import { RefreshTokenService } from '../../refresh-token/refresh-token.service';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('bcrypt');

jest.mock('../../common/functions', () => ({
  getEnvVar: jest.fn((key) => {
    if (key === 'JWT_SECRET') return 'jwtSecretKey';
    if (key === 'JWT_EXPIRATION') return '1h';
  }),
}));

describe('AuthService', () => {
  let service: AuthService;

  let usersServiceMock: {
    findOneForLogin: jest.Mock;
    findOneById: jest.Mock;
  };

  let jwtServiceMock: {
    sign: jest.Mock;
    verify: jest.Mock;
    decode: jest.Mock;
  };

  let prismaServiceMock: {
    refreshToken: {
      create: jest.Mock;
      findUnique: jest.Mock;
      update: jest.Mock;
      updateMany: jest.Mock;
    };
  };

  let refreshTokenServiceMock: {
    create: jest.Mock;
    rotate: jest.Mock;
    issueRefreshToken: jest.Mock;
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    usersServiceMock = {
      findOneForLogin: jest.fn(),
      findOneById: jest.fn(),
    };

    jwtServiceMock = {
      sign: jest.fn(),
      verify: jest.fn(),
      decode: jest.fn(),
    };

    prismaServiceMock = {
      refreshToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
      },
    };

    refreshTokenServiceMock = {
      create: jest.fn(),
      rotate: jest.fn(),
      issueRefreshToken: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersServiceMock },
        { provide: PrismaService, useValue: prismaServiceMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: RefreshTokenService, useValue: refreshTokenServiceMock },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    const loginDto: LoginDto = {
      username: faker.internet.username(),
      password: faker.internet.password(),
    };

    const findOneMockResult: UserCredentials = {
      id: faker.number.int(),
      username: loginDto.username,
      password: loginDto.password,
    };

    it('should return the authenticated user', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      usersServiceMock.findOneForLogin.mockResolvedValue(findOneMockResult);

      const expectedResult: AuthenticatedUser = {
        id: findOneMockResult.id,
        username: findOneMockResult.username,
      };

      const result = await service.validateUser(
        loginDto.username,
        loginDto.password,
      );

      expect(usersServiceMock.findOneForLogin).toHaveBeenCalledWith(
        loginDto.username,
      );

      expect(bcrypt.compare).toHaveBeenCalledWith(
        loginDto.password,
        findOneMockResult.password,
      );

      expect(result).toEqual(expectedResult);
      expect(result).not.toHaveProperty('password');
    });

    it('should throw an UnauthorizedException if the user does not exist', async () => {
      usersServiceMock.findOneForLogin.mockResolvedValue(null);

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw an UnauthorizedException if the password does not match', async () => {
      usersServiceMock.findOneForLogin.mockResolvedValue(findOneMockResult);

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(UnauthorizedException);

      expect(usersServiceMock.findOneForLogin).toHaveBeenCalledWith(
        loginDto.username,
      );

      expect(bcrypt.compare).toHaveBeenCalledWith(
        loginDto.password,
        findOneMockResult.password,
      );
    });
  });

  describe('login', () => {
    it('should return access_token and refresh_token', async () => {
      const user: AuthenticatedUser = {
        id: 1,
        username: 'username',
      };
      const accessToken = 'accessToken';
      const refreshToken = 'refreshToken';

      jest.spyOn(service, 'issueAccessToken').mockReturnValue(accessToken);
      refreshTokenServiceMock.create.mockResolvedValue(refreshToken);

      expect(await service.login(user)).toEqual({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
    });
  });

  describe('refreshTokens', () => {
    const refreshToken = 'oldRefreshToken';
    const user: AuthenticatedUser = {
      id: 1,
      username: 'username',
    };
    const newRefreshToken = 'newRefreshToken';
    const newAccessToken = 'newAccessToken';

    it('should return new acces token & refresh token', async () => {
      const decodeMockResult = { sub: 1, id: '123-456-789' };
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);

      usersServiceMock.findOneById.mockResolvedValue(user);

      const spyissueAccessToken = jest
        .spyOn(service, 'issueAccessToken')
        .mockReturnValue(newAccessToken);

      refreshTokenServiceMock.rotate.mockResolvedValue(newRefreshToken);

      expect(await service.refreshTokens(refreshToken)).toEqual({
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
      });
      expect(usersServiceMock.findOneById).toHaveBeenCalledWith(user.id);
      expect(spyissueAccessToken).toHaveBeenCalledWith({
        username: user.username,
        sub: user.id,
      });
      expect(refreshTokenServiceMock.rotate).toHaveBeenCalledWith(
        refreshToken,
        user,
      );
    });
  });

  describe('issueAccessToken', () => {
    it('should create and return an accessToken', () => {
      const payload: CreateJwtPayload = { sub: 1, username: 'username' };
      const jwtMockResult = 'jsonWebToken';
      jwtServiceMock.sign.mockReturnValue(jwtMockResult);

      expect(service.issueAccessToken(payload)).toEqual(jwtMockResult);
      expect(jwtServiceMock.sign).toHaveBeenCalledWith(payload, {
        expiresIn: '1h',
        secret: 'jwtSecretKey',
      });
      expect(getEnvVar).toHaveBeenLastCalledWith('JWT_EXPIRATION');
      expect(getEnvVar).toHaveBeenNthCalledWith(1, 'JWT_SECRET');
    });
  });
});
