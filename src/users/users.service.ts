import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PublicUser, UserCredentials } from './types/user.types';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from 'generated/prisma/runtime/library';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  private readonly logger = new Logger(UsersService.name);

  async findOneForLogin(username: string): Promise<UserCredentials | null> {
    try {
      return await this.prisma.user.findUnique({
        where: { username },
        select: {
          id: true,
          username: true,
          password: true,
        },
      });
    } catch (error) {
      this.logger.error(
        `Error finding user for login with username ${username}`,
        error,
      );
      throw new InternalServerErrorException();
    }
  }

  async findOneById(id: number): Promise<PublicUser | null> {
    try {
      return await this.prisma.user.findUnique({
        where: { id },
        select: {
          id: true,
          username: true,
          email: true,
        },
      });
    } catch (error) {
      this.logger.error(`Error finding user with id : ${id}`, error);
      throw new InternalServerErrorException();
    }
  }

  async createUser(createUserDto: CreateUserDto): Promise<PublicUser> {
    try {
      const cryptedPassword = await bcrypt.hash(createUserDto.password, 10);
      const user = await this.prisma.user.create({
        data: {
          username: createUserDto.username,
          email: createUserDto.email,
          password: cryptedPassword,
        },
      });

      return {
        id: user.id,
        username: user.username,
        email: user.email,
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        throw new ConflictException('Username or email already exists');
      }
      this.logger.error(`Error creating user`, error);
      throw new InternalServerErrorException();
    }
  }
}
