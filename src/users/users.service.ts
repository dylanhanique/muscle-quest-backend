import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PublicUser, UserCredentials } from './types/user.types';
import { CreateUserDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from '../../generated/prisma/runtime/library';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

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
      throw new InternalServerErrorException();
    }
  }

  //TODO: convertir createUserDto en interface
  async createUser(createUserDto: CreateUserDto): Promise<PublicUser> {
    try {
      const cryptedPassword = await bcrypt.hash(createUserDto.password, 10);

      return await this.prisma.user.create({
        data: {
          username: createUserDto.username,
          email: createUserDto.email,
          password: cryptedPassword,
        },
        select: { id: true, username: true, email: true },
      });
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('Username or email already exists');
      }
      throw new InternalServerErrorException();
    }
  }
}
