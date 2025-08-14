import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { UsersService } from '../../users/users.service';
import { LoginDto } from '../dto/login.dto';
import { faker } from '@faker-js/faker/.';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { UserCredentials } from 'src/users/types/user.types';
import { AuthenticatedUser, CreateJwtPayload } from '../types/auth.types';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import * as ms from 'ms';
import { v4 } from 'uuid';
import { getEnvVar } from '../../common/functions';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';
import { RefreshToken } from 'generated/prisma';

jest.mock('bcrypt');

jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

jest.mock('../../common/functions', () => ({
  getEnvVar: jest.fn((key) => {
    if (key === 'JWT_REFRESH_EXPIRATION') return '7d';
    if (key === 'JWT_SUPER_SECRET') return 'jwtSuperSecretKey';
    if (key === 'JWT_SECRET') return 'jwtSecretKey';
    if (key === 'JWT_EXPIRATION') return '1h';
  }),
  createHash: jest.fn(),
}));

jest.mock('ms');
const mockedMs = jest.mocked(ms, { shallow: true });

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

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: usersServiceMock },
        { provide: PrismaService, useValue: prismaServiceMock },
        { provide: JwtService, useValue: jwtServiceMock },
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

  describe('createAndStoreRefreshToken', () => {
    const jwtMsExpMockResult = 604800000;

    it('should create and return the refresh token', async () => {
      mockedMs.mockReturnValue(jwtMsExpMockResult);

      const jwtMockResult = 'jsonWebToken';
      jwtServiceMock.sign.mockReturnValue(jwtMockResult);

      const v4MockResult = '123-456-789';
      (v4 as jest.Mock).mockReturnValue(v4MockResult);

      const hashTokenMockResult = { hash: 'hashedToken', salt: 'tokenSalt' };
      jest.spyOn(service, 'hashToken').mockReturnValue(hashTokenMockResult);

      jest.spyOn(Date, 'now').mockReturnValue(1_000_000_000_000);

      const createTokenMockResult = {
        id: v4MockResult,
        userId: 1,
        tokenHash: hashTokenMockResult.hash,
        salt: hashTokenMockResult.salt,
        expiresAt: new Date(1_000_000_000_000 + jwtMsExpMockResult),
        createdAt: new Date(1_000_000_000_000),
        updatedAt: new Date(1_000_000_000_000),
        revoked: false,
      };

      prismaServiceMock.refreshToken.create.mockResolvedValue(
        createTokenMockResult,
      );
      const result = await service.createAndStoreRefreshToken(1);

      expect(getEnvVar).toHaveBeenNthCalledWith(1, 'JWT_REFRESH_EXPIRATION');
      expect(getEnvVar).toHaveBeenLastCalledWith('JWT_SUPER_SECRET');
      expect(ms).toHaveBeenCalledWith('7d');
      expect(jwtServiceMock.sign).toHaveBeenLastCalledWith(
        {
          id: v4MockResult,
          sub: createTokenMockResult.userId,
        },
        {
          expiresIn: '7d',
          secret: 'jwtSuperSecretKey',
        },
      );
      expect(prismaServiceMock.refreshToken.create).toHaveBeenCalledWith({
        data: {
          id: v4MockResult,
          userId: 1,
          tokenHash: hashTokenMockResult.hash,
          salt: hashTokenMockResult.salt,
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
    const decodeMockResult = { sub: 1, id: '123-456-789' };
    const refreshToken = 'oldRefreshToken';
    const hashedToken = 'oldRefreshTokenHashed';
    const storedRefreshToken: RefreshToken = {
      id: '123-456-789',
      tokenHash: hashedToken,
      salt: 'tokenSalt',
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
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue({});
      prismaServiceMock.refreshToken.findUnique.mockResolvedValue(
        storedRefreshToken,
      );
      usersServiceMock.findOneById.mockResolvedValue(user);

      jest.spyOn(service, 'ensureRefreshTokenMatches').mockReturnValue();

      prismaServiceMock.refreshToken.update.mockResolvedValue({
        ...storedRefreshToken,
        revoked: true,
      });

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
      expect(jwtServiceMock.verify).toHaveBeenCalledWith(refreshToken, {
        secret: 'jwtSuperSecretKey',
      });
      expect(prismaServiceMock.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { id: decodeMockResult.id },
      });
      expect(prismaServiceMock.refreshToken.update).toHaveBeenCalledWith({
        where: { id: storedRefreshToken.id },
        data: {
          revoked: true,
        },
      });
      expect(usersServiceMock.findOneById).toHaveBeenCalledWith(
        storedRefreshToken.userId,
      );
      expect(spyCASRF).toHaveBeenCalledWith(user.id);
      expect(spyCAT).toHaveBeenCalledWith({
        username: user.username,
        sub: user.id,
      });
    });

    it('should throw an UnauthorizedException if refresh token is not valid', async () => {
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue(
        new JsonWebTokenError('invalid signature'),
      );

      prismaServiceMock.refreshToken.updateMany.mockResolvedValue({
        ...storedRefreshToken,
        revoked: true,
      });

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prismaServiceMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: decodeMockResult.sub, revoked: false },
        data: { revoked: true },
      });
    });

    it('should throw an UnauthorizedException if refresh token is not found in DB', async () => {
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue({});
      prismaServiceMock.refreshToken.findUnique.mockResolvedValue(null);

      prismaServiceMock.refreshToken.updateMany.mockResolvedValue({
        ...storedRefreshToken,
        revoked: true,
      });

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prismaServiceMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: decodeMockResult.sub, revoked: false },
        data: { revoked: true },
      });
    });

    it('should throw an UnauthorizedException if user is not found in DB', async () => {
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue({});
      prismaServiceMock.refreshToken.findUnique.mockResolvedValue(
        storedRefreshToken,
      );
      usersServiceMock.findOneById.mockResolvedValue(null);

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prismaServiceMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: decodeMockResult.sub, revoked: false },
        data: { revoked: true },
      });
    });

    it('should throw an UnauthorizedException if tokens does not match', async () => {
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue({});
      prismaServiceMock.refreshToken.findUnique.mockResolvedValue(
        storedRefreshToken,
      );
      usersServiceMock.findOneById.mockResolvedValue(user);

      jest
        .spyOn(service, 'ensureRefreshTokenMatches')
        .mockImplementation(() => {
          throw new UnauthorizedException();
        });

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        UnauthorizedException,
      );
      expect(prismaServiceMock.refreshToken.updateMany).toHaveBeenCalledWith({
        where: { userId: decodeMockResult.sub, revoked: false },
        data: { revoked: true },
      });
    });

    it('should throw an InternalServerErrorException for other errors like Prisma error', async () => {
      jwtServiceMock.decode.mockReturnValue(decodeMockResult);
      jwtServiceMock.verify.mockReturnValue({});
      prismaServiceMock.refreshToken.findUnique.mockRejectedValue(
        PrismaClientUnknownRequestError,
      );

      await expect(service.refreshTokens(refreshToken)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('createAccessToken', () => {
    it('should create and return an accessToken', () => {
      const payload: CreateJwtPayload = { sub: 1, username: 'username' };
      const jwtMockResult = 'jsonWebToken';
      jwtServiceMock.sign.mockReturnValue(jwtMockResult);

      expect(service.createAccessToken(payload)).toEqual(jwtMockResult);
      expect(jwtServiceMock.sign).toHaveBeenCalledWith(payload, {
        expiresIn: '1h',
        secret: 'jwtSecretKey',
      });
      expect(getEnvVar).toHaveBeenLastCalledWith('JWT_EXPIRATION');
      expect(getEnvVar).toHaveBeenNthCalledWith(1, 'JWT_SECRET');
    });
  });

  describe('ensureRefreshTokenMatches', () => {
    const refreshToken = 'refreshToken';

    const storedRefreshToken: RefreshToken = {
      id: '123-456-789',
      tokenHash: 'tokenHash',
      salt: 'tokenSalt',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdAt: new Date(Date.now()),
      updatedAt: new Date(Date.now()),
      revoked: false,
      userId: 1,
    };

    it('should not throw if tokens match', () => {
      const spyHashToken = jest.spyOn(service, 'hashToken').mockReturnValue({
        hash: storedRefreshToken.tokenHash,
        salt: storedRefreshToken.salt,
      });

      expect(() => {
        service.ensureRefreshTokenMatches(refreshToken, storedRefreshToken);
      }).not.toThrow();
      expect(spyHashToken).toHaveBeenCalledWith(
        refreshToken,
        storedRefreshToken.salt,
      );
    });

    it('should throw if tokens does not match', () => {
      const invalidToken = 'invalidToken';

      jest.spyOn(service, 'hashToken').mockReturnValue({
        hash: 'invalidHash',
        salt: storedRefreshToken.salt,
      });

      expect(() => {
        service.ensureRefreshTokenMatches(invalidToken, storedRefreshToken);
      }).toThrow(UnauthorizedException);
    });

    it('should throw if token is revoked', () => {
      const revokedToken = { ...storedRefreshToken, revoked: true };

      jest.spyOn(service, 'hashToken').mockReturnValue({
        hash: storedRefreshToken.tokenHash,
        salt: storedRefreshToken.salt,
      });

      expect(() => {
        service.ensureRefreshTokenMatches(refreshToken, revokedToken);
      }).toThrow(UnauthorizedException);
    });
  });
});
