import { faker } from '@faker-js/faker';
import { PrismaService } from '../src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import * as ms from 'ms';
import { v4 as uuidv4 } from 'uuid';
import { RefreshToken, Workout } from '../generated/prisma';
import { PublicUser } from '../src/user/types/user.types';
import { RefreshTokenTestFixture, UserTestFixture } from './types/test-types';
import { JwtService } from '@nestjs/jwt';
import { getEnvVar } from '../src/common/functions';
import { createHash, randomBytes } from 'node:crypto';

export class TestUtils {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async resetDatabase() {
    const tablenames = await this.prismaService.$queryRaw<
      Array<{ tablename: string }>
    >`SELECT tablename FROM pg_tables WHERE schemaname='public'`;

    for (const { tablename } of tablenames) {
      if (tablename !== '_prisma_migrations') {
        try {
          await this.prismaService.$executeRawUnsafe(
            `TRUNCATE TABLE "${tablename}" RESTART IDENTITY CASCADE;`,
          );
        } catch (err) {
          console.error(`Error on truncate table: ${tablename}`, err);
        }
      }
    }
  }

  async createUserTestFixture(): Promise<UserTestFixture> {
    const password = faker.internet.password();

    const user: PublicUser = await this.prismaService.user.create({
      data: {
        username: faker.internet.username(),
        email: faker.internet.email(),
        password: await bcrypt.hash(password, 10),
      },
      select: { id: true, username: true, email: true },
    });

    return { password, user };
  }

  createJwt(userId: number, username: string): string {
    return this.jwtService.sign(
      { sub: userId, username },
      {
        secret: getEnvVar('JWT_SECRET'),
        expiresIn: getEnvVar('JWT_EXPIRATION'),
      },
    );
  }

  async createRefreshTokenTestFixture(
    userId: number,
  ): Promise<RefreshTokenTestFixture> {
    const jwtRefreshExp = getEnvVar('JWT_REFRESH_EXPIRATION');
    const msJwtRefreshExp = ms(jwtRefreshExp as ms.StringValue);
    const expirationDate = new Date(Date.now() + msJwtRefreshExp);

    const refreshTokenId = uuidv4();
    const payload = { id: refreshTokenId, sub: userId };
    const refreshToken = this.jwtService.sign(payload, {
      secret: getEnvVar('JWT_SUPER_SECRET'),
      expiresIn: jwtRefreshExp,
    });
    const salt = randomBytes(16).toString('hex');
    const tokenHash = createHash('sha256')
      .update(salt + refreshToken)
      .digest('hex');

    const storedRefreshToken: RefreshToken =
      await this.prismaService.refreshToken.create({
        data: {
          id: refreshTokenId,
          userId,
          tokenHash,
          salt,
          expiresAt: expirationDate,
        },
      });

    return { refreshToken, storedRefreshToken };
  }

  async createWorkoutTestFixture(userId: number): Promise<Workout> {
    return await this.prismaService.workout.create({
      data: {
        userId,
        name: faker.word.words(2),
      },
    });
  }
}
