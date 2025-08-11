import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from '../jwt.strategy';
import { UsersService } from '../../users/users.service';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';

let usersServiceMock: {
  findOneById: jest.Mock;
};

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
        { provide: UsersService, useValue: usersServiceMock },
      ],
    }).compile();

    service = module.get<JwtStrategy>(JwtStrategy);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validate', () => {
    it('should return the validated user', async () => {
      const user = {
        id: 1,
        username: 'username',
        email: 'email@email.email',
      };

      usersServiceMock.findOneById.mockResolvedValue(user);
      expect(
        await service.validate({ sub: user.id, username: user.username }),
      ).toEqual(user);
    });

    it('should return an UnauthorizedException if user does not exist', async () => {
      usersServiceMock.findOneById.mockResolvedValue(null);

      await expect(
        service.validate({ sub: 1, username: 'username' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return an InternalServerException for other errors', async () => {
      usersServiceMock.findOneById.mockRejectedValue(
        PrismaClientUnknownRequestError,
      );

      await expect(
        service.validate({ sub: 1, username: 'username' }),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });
});
