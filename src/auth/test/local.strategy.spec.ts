import { Test, TestingModule } from '@nestjs/testing';
import { LocalStrategy } from '../local.strategy';
import { AuthService } from '../auth.service';
import { AuthenticatedUser } from '../types/auth.types';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';

let authServiceMock: {
  validateUser: jest.Mock;
};

describe('LocalStrategy', () => {
  let service: LocalStrategy;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    authServiceMock = {
      validateUser: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LocalStrategy,
        { provide: AuthService, useValue: authServiceMock },
      ],
    }).compile();

    service = module.get<LocalStrategy>(LocalStrategy);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validate', () => {
    it('should return the authenticated user', async () => {
      const user: AuthenticatedUser = {
        id: 1,
        username: 'username',
      };

      authServiceMock.validateUser.mockResolvedValue(user);
      expect(await service.validate('username', 'password')).toEqual(user);
    });

    it('should throw an UnauthorizedException if credentials are not valid', async () => {
      authServiceMock.validateUser.mockRejectedValue(
        new UnauthorizedException(),
      );
      await expect(
        service.validate('username', 'wrongPassword'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return an InternalServerException for other errors', async () => {
      authServiceMock.validateUser.mockRejectedValue(
        new InternalServerErrorException(),
      );

      await expect(service.validate('username', 'password')).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});
