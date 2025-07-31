import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from '../users.service';
import { faker } from '@faker-js/faker';
import { CreateUserDto } from '../dto/create-user.dto';
import { PrismaService } from '../../prisma/prisma.service';
import { PrismaClientKnownRequestError } from '../../../generated/prisma/runtime/library';
import { ConflictException } from '@nestjs/common';

describe('UsersService', () => {
  let service: UsersService;
  let prismaMock: {
    user: {
      create: jest.Mock;
    };
  };

  beforeEach(async () => {
    prismaMock = {
      user: {
        create: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: PrismaService, useValue: prismaMock },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createUser', () => {
    it('should return the created user : id, username and email', async () => {
      const createUserDto: CreateUserDto = {
        username: faker.internet.username(),
        email: faker.internet.email(),
        password: faker.internet.password(),
      };

      const mockResult = {
        id: faker.number.int(),
        username: createUserDto.username,
        email: createUserDto.email,
      };

      prismaMock.user.create.mockResolvedValue(mockResult);

      const result = await service.createUser(createUserDto);

      expect(result).toEqual(mockResult);
      expect(result).not.toHaveProperty('password');
      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          username: createUserDto.username,
          email: createUserDto.email,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          password: expect.any(String),
        },
      });
    });

    it('should throw a ConflictException if credentials are already used', async () => {
      const createUserDto: CreateUserDto = {
        username: faker.internet.username(),
        email: faker.internet.email(),
        password: faker.internet.password(),
      };

      prismaMock.user.create.mockRejectedValue(
        new PrismaClientKnownRequestError('', {
          clientVersion: '',
          code: 'P2002',
        }),
      );

      await expect(service.createUser(createUserDto)).rejects.toThrow(
        ConflictException,
      );
      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          username: createUserDto.username,
          email: createUserDto.email,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          password: expect.any(String),
        },
      });
    });

    it('should throw an InternalServerErrorException for other errors', async () => {
      const createUserDto: CreateUserDto = {
        username: faker.internet.username(),
        email: faker.internet.email(),
        password: faker.internet.password(),
      };

      prismaMock.user.create.mockRejectedValue(new Error());

      await expect(service.createUser(createUserDto)).rejects.toThrow(
        'Internal Server Error',
      );
      expect(prismaMock.user.create).toHaveBeenCalledWith({
        data: {
          username: createUserDto.username,
          email: createUserDto.email,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          password: expect.any(String),
        },
      });
    });
  });
});
