import { Test, TestingModule } from '@nestjs/testing';
import { RefreshTokenService } from '../refresh-token.service';
import { PrismaService } from '../../prisma/prisma.service';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { RefreshToken } from '../../../generated/prisma';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { v4 } from 'uuid';
import { getEnvVar } from '../../common/functions';
import * as ms from 'ms';
import { UsersService } from '../../users/users.service';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';

jest.mock('../common/functions', () => ({
  getEnvVar: jest.fn((key) => {
    if (key === 'JWT_REFRESH_EXPIRATION') return '7d';
    if (key === 'JWT_SUPER_SECRET') return 'jwtSuperSecretKey';
  }),
}));

jest.mock('ms');
const mockedMs = jest.mocked(ms, { shallow: true });

jest.mock('uuid', () => ({
  v4: jest.fn(),
}));

let prismaServiceMock: {
  refreshToken: {
    create: jest.Mock;
    findUnique: jest.Mock;
    update: jest.Mock;
    updateMany: jest.Mock;
  };
};

let usersServiceMock: {
  findOneById: jest.Mock;
};

let jwtServiceMock: {
  sign: jest.Mock;
  decode: jest.Mock;
  verify: jest.Mock;
};

describe('RefreshTokenService', () => {
  let service: RefreshTokenService;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    prismaServiceMock = {
      refreshToken: {
        create: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
      },
    };

    usersServiceMock = {
      findOneById: jest.fn(),
    };

    jwtServiceMock = {
      sign: jest.fn(),
      decode: jest.fn(),
      verify: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefreshTokenService,
        { provide: PrismaService, useValue: prismaServiceMock },
        { provide: JwtService, useValue: jwtServiceMock },
        { provide: UsersService, useValue: usersServiceMock },
      ],
    }).compile();

    service = module.get<RefreshTokenService>(RefreshTokenService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('hashRefreshToken', () => {
    it.todo('should return a hashed refresh token');
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
      const spyHashToken = jest
        .spyOn(service, 'hashRefreshToken')
        .mockReturnValue({
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

      jest.spyOn(service, 'hashRefreshToken').mockReturnValue({
        hash: 'invalidHash',
        salt: storedRefreshToken.salt,
      });

      expect(() => {
        service.ensureRefreshTokenMatches(invalidToken, storedRefreshToken);
      }).toThrow(UnauthorizedException);
    });

    it('should throw if token is revoked', () => {
      const revokedToken = { ...storedRefreshToken, revoked: true };

      jest.spyOn(service, 'hashRefreshToken').mockReturnValue({
        hash: storedRefreshToken.tokenHash,
        salt: storedRefreshToken.salt,
      });

      expect(() => {
        service.ensureRefreshTokenMatches(refreshToken, revokedToken);
      }).toThrow(UnauthorizedException);
    });
  });

  describe('issueRefreshToken', () => {
    const jwtMsExpMockResult = 604800000;

    it('should create and return the refresh token', async () => {
      mockedMs.mockReturnValue(jwtMsExpMockResult);

      const jwtMockResult = 'jsonWebToken';
      jwtServiceMock.sign.mockReturnValue(jwtMockResult);

      const v4MockResult = '123-456-789';
      (v4 as jest.Mock).mockReturnValue(v4MockResult);

      const hashTokenMockResult = { hash: 'hashedToken', salt: 'tokenSalt' };
      jest
        .spyOn(service, 'hashRefreshToken')
        .mockReturnValue(hashTokenMockResult);

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
      const result = await service.issueRefreshToken(1);

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

      await expect(service.issueRefreshToken(1)).rejects.toThrow(
        InternalServerErrorException,
      );
    });

    it('should throw an InternalServerErrorException if JWT_REFRESH_EXPIRATION has an invalid format', async () => {
      (getEnvVar as jest.Mock).mockImplementationOnce((key) => {
        if (key === 'JWT_REFRESH_EXPIRATION') return 'invalidFormat';
      });

      mockedMs.mockReturnValue(undefined as any);

      await expect(service.issueRefreshToken(1)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('rotate', () => {
    const decodeMockResult = { sub: 1, id: '123-456-789' };
    const refreshToken = 'oldRefreshToken';
    const newRefreshToken = 'newRefreshToken';
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

    it('should return the new refresh token', async () => {
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

      const spyIssueRefreshToken = jest
        .spyOn(service, 'issueRefreshToken')
        .mockResolvedValue(newRefreshToken);

      expect(await service.rotate(refreshToken, user.id)).toEqual(
        newRefreshToken,
      );

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
      expect(spyIssueRefreshToken).toHaveBeenCalledWith(user.id);
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

      await expect(service.rotate(refreshToken, user.id)).rejects.toThrow(
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

      await expect(service.rotate(refreshToken, user.id)).rejects.toThrow(
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

      await expect(service.rotate(refreshToken, user.id)).rejects.toThrow(
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

      await expect(service.rotate(refreshToken, user.id)).rejects.toThrow(
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

      await expect(service.rotate(refreshToken, user.id)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
