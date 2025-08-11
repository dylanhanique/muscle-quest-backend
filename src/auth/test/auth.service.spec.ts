import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { UsersService } from '../../users/users.service';
import { LoginDto } from '../dto/login.dto';
import { faker } from '@faker-js/faker/.';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { UserCredentials } from 'src/users/types/user.types';
import { AuthenticatedUser } from '../types/auth.types';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import * as ms from 'ms';
import { getEnvVar, hashToken } from '../../common/functions';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';

jest.mock('bcrypt');

jest.mock('../../common/functions', () => ({
  getEnvVar: jest.fn((key) => {
    if (key === 'JWT_REFRESH_EXPIRATION') return '7d';
    if (key === 'JWT_SUPER_SECRET') return 'jwtSuperSecretKey';
    return undefined;
  }),
  hashToken: jest.fn(),
}));

jest.mock('ms');
const mockedMs = jest.mocked(ms, { shallow: true });

test('mock getEnvVar fonctionne', () => {
  expect(getEnvVar('JWT_REFRESH_EXPIRATION')).toBe('7d');
  expect(getEnvVar('JWT_SUPER_SECRET')).toBe('jwtSuperSecretKey');
  expect(getEnvVar('foo')).toBe(undefined); // ici tu sais que c’est ta chaîne pas undefined natif
});

describe('AuthService', () => {
  let service: AuthService;

  let userMock: {
    findOneForLogin: jest.Mock;
    findOneById: jest.Mock;
  };

  let jwtMock: {
    sign: jest.Mock;
    verify: jest.Mock;
  };

  let prismaMock: {
    refreshToken: {
      create: jest.Mock;
      findUnique: jest.Mock;
    };
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    userMock = {
      findOneForLogin: jest.fn(),
      findOneById: jest.fn(),
    };

    jwtMock = {
      sign: jest.fn(),
      verify: jest.fn(),
    };

    prismaMock = {
      refreshToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: userMock },
        { provide: PrismaService, useValue: prismaMock },
        { provide: JwtService, useValue: jwtMock },
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

      userMock.findOneForLogin.mockResolvedValue(findOneMockResult);

      const expectedResult: AuthenticatedUser = {
        id: findOneMockResult.id,
        username: findOneMockResult.username,
      };

      const result = await service.validateUser(
        loginDto.username,
        loginDto.password,
      );

      expect(userMock.findOneForLogin).toHaveBeenCalledWith(loginDto.username);

      expect(bcrypt.compare).toHaveBeenCalledWith(
        loginDto.password,
        findOneMockResult.password,
      );

      expect(result).toEqual(expectedResult);
      expect(result).not.toHaveProperty('password');
    });

    it('should throw an UnauthorizedException if the user does not exist', async () => {
      userMock.findOneForLogin.mockResolvedValue(null);

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw an UnauthorizedException if the password does not match', async () => {
      userMock.findOneForLogin.mockResolvedValue(findOneMockResult);

      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(UnauthorizedException);

      expect(userMock.findOneForLogin).toHaveBeenCalledWith(loginDto.username);

      expect(bcrypt.compare).toHaveBeenCalledWith(
        loginDto.password,
        findOneMockResult.password,
      );
    });
  });

  describe('createAndStoreRefreshToken', () => {
    const jwtMsExpMockResult = 604800000;

    it('should create and return the refresh token', async () => {
      mockedMs.mockReturnValue(jwtMsExpMockResult);

      const jwtMockResult =
        'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MzI2MzgxMDYsImV4cCI6MTczMjY5MjUwOSwibmJmIjoxNzA1MDgxNjQ4LCJpc3MiOiJHdXRrb3dza2kgYW5kIFNvbnMiLCJzdWIiOiJlMzQxZjMwNS0yM2I2LTRkYmQtOTY2ZC1iNDRiZmM0ZGIzMGUiLCJhdWQiOiI0YzMwZGE3Yi0zZDUzLTQ4OGUtYTAyZC0zOWI2MDZiZmYxMTciLCJqdGkiOiJiMGZmOTMzOC04ODMwLTRmNDgtYjA3Ny1kNDNmMjU2OGZlYzAifQ';
      jwtMock.sign.mockReturnValue(jwtMockResult);

      (hashToken as jest.Mock).mockReturnValue(
        'f01714144b21786288003905ebfa9d10acdd0f43dca2d18bb77b582d519eb747',
      );
      const hashedToken = hashToken(jwtMockResult);

      jest.spyOn(Date, 'now').mockReturnValue(1_000_000_000_000);

      const mockResult = {
        id: 1,
        userId: 1,
        tokenHash: hashedToken,
        expiresAt: new Date(1_000_000_000_000 + jwtMsExpMockResult),
        createdAt: new Date(1_000_000_000_000),
        updatedAt: new Date(1_000_000_000_000),
        revoked: false,
      };

      prismaMock.refreshToken.create.mockResolvedValue(mockResult);
      const result = await service.createAndStoreRefreshToken(1);

      expect(getEnvVar).toHaveBeenNthCalledWith(1, 'JWT_REFRESH_EXPIRATION');
      expect(getEnvVar).toHaveBeenLastCalledWith('JWT_SUPER_SECRET');
      expect(ms).toHaveBeenCalledWith('7d');
      expect(jwtMock.sign).toHaveBeenLastCalledWith(
        {},
        {
          expiresIn: '7d',
          secret: 'jwtSuperSecretKey',
        },
      );
      expect(prismaMock.refreshToken.create).toHaveBeenCalledWith({
        data: {
          userId: 1,
          tokenHash: hashedToken,
          expiresAt: new Date(1_000_000_000_000 + jwtMsExpMockResult),
        },
      });
      expect(result).toEqual(jwtMockResult);
    });

    it('should throw an InternalServerErrorException if an env var is missing', async () => {
      (getEnvVar as jest.Mock).mockImplementationOnce(() => {
        throw new Error();
      });

      await expect(service.createAndStoreRefreshToken(1)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw an InternalServerErrorException if JWT_REFRESH_EXPIRATION has an invalid format', async () => {
      (getEnvVar as jest.Mock).mockImplementationOnce((key) => {
        if (key === 'JWT_REFRESH_EXPIRATION') return 'invalidFormat';
      });

      mockedMs.mockReturnValue(undefined as any);

      await expect(service.createAndStoreRefreshToken(1)).rejects.toThrow(
        InternalServerErrorException,
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

      jest.spyOn(service, 'createAccessToken').mockReturnValue(accessToken);
      jest
        .spyOn(service, 'createAndStoreRefreshToken')
        .mockResolvedValue(refreshToken);

      expect(await service.login(user)).toEqual({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
    });
  });

  describe('refreshTokens', () => {
    const refreshToken = 'oldRefreshToken';
    const hashedToken = 'oldRefreshTokenHashed';
    const storedHashedToken = {
      id: 1,
      tokenHash: hashedToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdAt: new Date(Date.now()),
      updatedAt: new Date(Date.now()),
      revoked: false,
      userId: 1,
    };
    const user = {
      id: 1,
      username: 'username',
      email: 'email@email.email',
    };
    const newRefreshToken = 'newRefreshToken';
    const newAccessToken = 'newAccessToken';

    it('should return new access & refresh tokens when refresh token is valid', async () => {
      jwtMock.verify.mockReturnValue({});
      (hashToken as jest.Mock).mockReturnValue(hashedToken);
      prismaMock.refreshToken.findUnique.mockResolvedValue(storedHashedToken);
      userMock.findOneById.mockResolvedValue(user);
      const spyCASRF = jest
        .spyOn(service, 'createAndStoreRefreshToken')
        .mockResolvedValue(newRefreshToken);
      const spyCAT = jest
        .spyOn(service, 'createAccessToken')
        .mockReturnValue(newAccessToken);

      expect(await service.refreshTokens(refreshToken)).toEqual({
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
      });
      expect(getEnvVar).toHaveBeenCalledWith('JWT_SUPER_SECRET');
      expect(jwtMock.verify).toHaveBeenCalledWith(refreshToken, {
        secret: 'jwtSuperSecretKey',
      });
      expect(prismaMock.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { tokenHash: hashedToken },
      });
      expect(userMock.findOneById).toHaveBeenCalledWith(
        storedHashedToken.userId,
      );
      expect(spyCASRF).toHaveBeenCalledWith(user.id);
      expect(spyCAT).toHaveBeenCalledWith({
        username: user.username,
        sub: user.id,
      });
    });

    it('should throw an UnauthorizedException if refresh token is not valid', async () => {
      jwtMock.verify.mockReturnValue(
        new JsonWebTokenError('invalid signature'),
      );

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw an UnauthorizedException if refresh token is not found in DB', async () => {
      jwtMock.verify.mockReturnValue({});
      (hashToken as jest.Mock).mockReturnValue(hashedToken);
      prismaMock.refreshToken.findUnique.mockResolvedValue(null);

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw an UnauthorizedException if user is not found in DB', async () => {
      jwtMock.verify.mockReturnValue({});
      (hashToken as jest.Mock).mockReturnValue(hashedToken);
      prismaMock.refreshToken.findUnique.mockResolvedValue(storedHashedToken);
      userMock.findOneById.mockResolvedValue(null);

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw an InternalServerErrorException for other errors like Prisma error', async () => {
      jwtMock.verify.mockReturnValue({});
      (hashToken as jest.Mock).mockReturnValue(hashedToken);
      prismaMock.refreshToken.findUnique.mockRejectedValue(
        PrismaClientUnknownRequestError,
      );

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
