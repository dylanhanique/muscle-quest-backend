import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from '../jwt.strategy';
import { UserService } from '../../user/user.service';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';
import { JwtPayload } from '../types/auth.types';

let usersServiceMock: {
  findOneById: jest.Mock;
};

jest.mock('../../common/functions', () => ({
  getEnvVar: jest.fn((key) => {
    if (key === 'JWT_SECRET') return 'jwtSecretKey';
  }),
}));

describe('JwtStrategy', () => {
  let service: JwtStrategy;
  usersServiceMock = {
    findOneById: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        { provide: UserService, useValue: usersServiceMock },
      ],
    }).compile();

    service = module.get<JwtStrategy>(JwtStrategy);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validate', () => {
    const jwtPayload: JwtPayload = {
      sub: 1,
      username: 'username',
      iat: 1700000000,
      exp: 1700000000,
    };

    it('should return the validated user', async () => {
      const user = {
        id: 1,
        username: 'username',
        email: 'email@email.email',
      };

      usersServiceMock.findOneById.mockResolvedValue(user);
      expect(await service.validate(jwtPayload)).toEqual(user);
    });

    it('should return an UnauthorizedException if user does not exist', async () => {
      usersServiceMock.findOneById.mockResolvedValue(null);

      await expect(
        service.validate({ ...jwtPayload, username: 'username' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return an InternalServerException for other errors', async () => {
      usersServiceMock.findOneById.mockRejectedValue(
        PrismaClientUnknownRequestError,
      );

      await expect(service.validate(jwtPayload)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
