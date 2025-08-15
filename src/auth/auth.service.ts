import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { AuthenticatedUser, CreateJwtPayload } from './types/auth.types';
import { getEnvVar } from '../common/functions';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { RefreshTokenService } from '../refresh-token/refresh-token.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
  ) {}

  async validateUser(
    username: string,
    password: string,
  ): Promise<AuthenticatedUser> {
    try {
      const user = await this.usersService.findOneForLogin(username);

      const passwordMatches = user
        ? await bcrypt.compare(password, user.password)
        : false;

      if (user && passwordMatches) {
        const { password: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
      } else {
        throw new UnauthorizedException();
      }
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new InternalServerErrorException();
    }
  }

  issueAccessToken(payload: CreateJwtPayload): string {
    return this.jwtService.sign(payload, {
      secret: getEnvVar('JWT_SECRET'),
      expiresIn: getEnvVar('JWT_EXPIRATION'),
    });
  }

  async login(user: AuthenticatedUser) {
    const payload: CreateJwtPayload = { username: user.username, sub: user.id };
    return {
      access_token: this.issueAccessToken(payload),
      refresh_token: await this.refreshTokenService.issueRefreshToken(user.id),
    };
  }

  //TODO: logout

  async refreshTokens(refreshToken: string, user: AuthenticatedUser) {
    try {
      const payload: CreateJwtPayload = {
        username: user.username,
        sub: user.id,
      };

      return {
        access_token: this.issueAccessToken(payload),
        refresh_token: await this.refreshTokenService.rotate(
          refreshToken,
          user.id,
        ),
      };
    } catch (error) {
      if (
        error instanceof UnauthorizedException ||
        error instanceof InternalServerErrorException
      ) {
        throw error;
      } else {
        throw new InternalServerErrorException(
          'An unexpected error occured during refresh tokens',
        );
      }
    }
  }
}
