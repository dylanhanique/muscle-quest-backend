import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { UsersService } from '../../users/users.service';
import { LoginDto } from '../dto/login.dto';
import { faker } from '@faker-js/faker/.';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { UserCredentials } from 'src/users/types/user.types';
import { AuthenticatedUser } from '../types/auth.types';
import {
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaClientInitializationError } from '../../../generated/prisma/runtime/library';

jest.mock('bcrypt');

describe('AuthService', () => {
  let service: AuthService;
  let userMock: {
    findOneForLogin: jest.Mock;
  };

  beforeEach(async () => {
    userMock = {
      findOneForLogin: jest.fn(),
    };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UsersService, useValue: userMock },
        PrismaService,
        JwtService,
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateUser', () => {
    it('should return the authenticated user', async () => {
      const loginDto: LoginDto = {
        username: faker.internet.username(),
        password: faker.internet.password(),
      };

      const findOneMockResult: UserCredentials = {
        id: faker.number.int(),
        username: loginDto.username,
        password: loginDto.password,
      };

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
      const loginDto: LoginDto = {
        username: faker.internet.username(),
        password: faker.internet.password(),
      };

      userMock.findOneForLogin.mockResolvedValue(null);

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw an UnauthorizedException if the password does not match', async () => {
      const loginDto: LoginDto = {
        username: faker.internet.username(),
        password: 'wrongPassword',
      };

      const findOneMockResult: UserCredentials = {
        id: faker.number.int(),
        username: loginDto.username,
        password: 'correctPassword',
      };

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

    it('should throw an UnauthorizedException for all other errors', async () => {
      const loginDto: LoginDto = {
        username: faker.internet.username(),
        password: 'wrongPassword',
      };

      userMock.findOneForLogin.mockRejectedValue(
        new PrismaClientInitializationError('', ''),
      );

      await expect(
        service.validateUser(loginDto.username, loginDto.password),
      ).rejects.toThrow(InternalServerErrorException);
      expect(userMock.findOneForLogin).toHaveBeenCalledWith(loginDto.username);
    });
  });
});
