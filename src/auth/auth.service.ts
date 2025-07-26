import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { AuthenticatedUser, JwtPayload } from './types/auth.types';
import { getEnvVar, hashToken } from '../common/functions';
import { PrismaService } from '../prisma/prisma.service';
import * as ms from 'ms';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  private readonly logger = new Logger(AuthService.name);

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
        throw new UnauthorizedException('Invalid credentials');
      }
    } catch (error) {
      if (!(error instanceof UnauthorizedException)) {
        this.logger.error('Unexpected error validating user:', error);
      }
      throw new UnauthorizedException();
    }
  }

  async login(user: AuthenticatedUser) {
    const payload: JwtPayload = { username: user.username, sub: user.id };
    return {
      tokens: {
        access_token: this.jwtService.sign(payload, {
          secret: getEnvVar('JWT_SECRET'),
          expiresIn: getEnvVar('JWT_EXPIRATION'),
        }),
        refresh_token: await this.createAndStoreRefreshToken(user.id),
      },
    };
  }

  async createAndStoreRefreshToken(userId: number): Promise<string> {
    const jwtRefreshExp = getEnvVar('JWT_REFRESH_EXPIRATION');
    const msJwtRefreshExp = ms(jwtRefreshExp as ms.StringValue);

    if (!msJwtRefreshExp) {
      this.logger.error(
        'Invalid JWT_REFRESH_EXPIRATION format:',
        jwtRefreshExp,
      );
      throw new Error('Invalid JWT_REFRESH_EXPIRATION format');
    }

    const newRefreshToken = this.jwtService.sign(
      {},
      {
        secret: getEnvVar('JWT_SUPER_SECRET'),
        expiresIn: jwtRefreshExp,
      },
    );

    const hashedToken = hashToken(newRefreshToken);

    try {
      await this.prisma.refreshToken.create({
        data: {
          userId,
          tokenHash: hashedToken,
          expiresAt: new Date(Date.now() + msJwtRefreshExp),
        },
      });
    } catch (error) {
      this.logger.error('Error storing refresh token in database:', error);
      throw new InternalServerErrorException('Unable to store refresh token');
    }

    return newRefreshToken;
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      this.jwtService.verify(refreshToken, {
        secret: getEnvVar('JWT_SUPER_SECRET'),
      });

      const hashedToken = hashToken(refreshToken);

      // TODO: add check for token expiration or revocation
      const storedHashedToken = await this.prisma.refreshToken.findUnique({
        where: { tokenHash: hashedToken },
      });

      if (!storedHashedToken) {
        this.logger.error('Invalid refresh token:', hashedToken);
        throw new UnauthorizedException('Invalid refresh token');
      }

      const user = await this.usersService.findOneById(
        storedHashedToken.userId,
      );

      if (!user) {
        this.logger.error(
          'User not found for refresh token:',
          storedHashedToken.userId,
        );
        throw new UnauthorizedException('User not found');
      }

      const newRefreshToken = await this.createAndStoreRefreshToken(user.id);

      const payload: JwtPayload = { username: user.username, sub: user.id };

      return {
        access_token: this.jwtService.sign(payload, {
          secret: getEnvVar('JWT_SECRET'),
          expiresIn: getEnvVar('JWT_EXPIRATION'),
        }),
        refresh_token: newRefreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        this.logger.error('Refresh token validation failed:', error.message);
        throw error;
      }

      this.logger.error('Unexpected error during refresh token:', error);
      throw new InternalServerErrorException('Failed to refresh access token');
    }
  }
}
