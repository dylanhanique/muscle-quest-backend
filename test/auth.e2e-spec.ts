import { HttpStatus } from '@nestjs/common';
import {
  httpServer,
  request,
  testUtils,
  prismaService,
  jwtService,
} from './jest.setup.e2e';
import { RefreshToken } from '../generated/prisma';
import { getEnvVar } from '../src/common/functions';
import { v4 as uuidv4 } from 'uuid';
import { UserTestFixture } from './types/test-types';

function expectAllRevoked(tokens: { revoked: boolean }[]) {
  expect(tokens).not.toHaveLength(0);
  expect(tokens.every((t) => t.revoked)).toBe(true);
}

describe('Auth e2e', () => {
  let userFixture: UserTestFixture;

  beforeEach(async () => {
    userFixture = await testUtils.createUserTestFixture();
  });

  describe('login', () => {
    it('should return access_token and refresh_token', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({
          username: userFixture.user.username,
          password: userFixture.password,
        });

      // response checks

      expect(res.status).toBe(HttpStatus.CREATED);
      expect(res.body).toHaveProperty('access_token');
      expect(res.body).toHaveProperty('refresh_token');
      expect(typeof res.body.refresh_token).toBe('string');
      expect(typeof res.body.access_token).toBe('string');

      // token validity

      expect(() => {
        jwtService.verify(res.body.refresh_token, {
          secret: getEnvVar('JWT_SUPER_SECRET'),
        });
      }).not.toThrow();
      expect(() => {
        jwtService.verify(res.body.access_token, {
          secret: getEnvVar('JWT_SECRET'),
        });
      }).not.toThrow();

      // db checks

      const decodedToken: RefreshToken = jwtService.decode(
        res.body.refresh_token,
      );

      const storedRefreshToken: RefreshToken | null =
        await prismaService.refreshToken.findUnique({
          where: { id: decodedToken.id, userId: userFixture.user.id },
        });
      expect(storedRefreshToken).not.toBeNull();
      expect(storedRefreshToken!.revoked).toBe(false);
    });

    it('should return 401 Unauthorized with wrong password', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({
          username: userFixture.user.username,
          password: 'wrongPassword',
        });

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);
    });
    it('should return 401 Unauthorized if user not in db', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: 'wrongUsername', password: 'wrongPassword' });

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);
    });

    it('should return 400 BadRequest if body has extra/unexpected properties', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({
          username: userFixture.user.username,
          password: userFixture.password,
          email: 'email',
        });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if username is missing', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ password: userFixture.password });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if username is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: '', password: userFixture.password });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if username is not a string', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: 123, password: userFixture.password });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if password is missing', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: userFixture.user.username });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if password is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: userFixture.user.username, password: '' });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if password is not a string', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({ username: userFixture.user.username, password: 123 });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if body is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/login')
        .send({});

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
  });

  describe('refresh-tokens', () => {
    const jwtRefreshExp = getEnvVar('JWT_REFRESH_EXPIRATION');
    let refreshToken: string;
    let storedRefreshToken: RefreshToken;

    beforeEach(async () => {
      ({ refreshToken, storedRefreshToken } =
        await testUtils.createRefreshTokenTestFixture(userFixture.user.id));
    });

    it('should return new access_token and refresh_tokens', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens')
        .send({ refreshToken });

      // response checks

      expect(res.status).toBe(HttpStatus.CREATED);
      expect(res.body).toHaveProperty('access_token');
      expect(res.body).toHaveProperty('refresh_token');
      expect(typeof res.body.refresh_token).toBe('string');
      expect(typeof res.body.access_token).toBe('string');

      // token validity

      const verifyRefreshToken = () => {
        jwtService.verify(res.body.refresh_token, {
          secret: getEnvVar('JWT_SUPER_SECRET'),
        });
      };

      const verifyAccessToken = () => {
        jwtService.verify(res.body.access_token, {
          secret: getEnvVar('JWT_SECRET'),
        });
      };

      expect(verifyRefreshToken).not.toThrow();
      expect(verifyAccessToken).not.toThrow();

      // db checks

      const decodedToken: RefreshToken = jwtService.decode(
        res.body.refresh_token,
      );

      const newRefreshToken: RefreshToken | null =
        await prismaService.refreshToken.findUnique({
          where: { id: decodedToken.id, userId: userFixture.user.id },
        });
      expect(newRefreshToken).not.toBeNull();
      expect(newRefreshToken!.revoked).toBe(false);

      const oldRefreshToken: RefreshToken | null =
        await prismaService.refreshToken.findUnique({
          where: { id: storedRefreshToken.id, userId: userFixture.user.id },
        });
      expect(oldRefreshToken).not.toBeNull();
      expect(oldRefreshToken!.revoked).toBe(true);
    });

    it('should return 401 Unauthorized and revoke all user tokens if refresh token not in db', async () => {
      const payload = { id: uuidv4(), sub: userFixture.user.id };
      const rt = jwtService.sign(payload, {
        secret: getEnvVar('JWT_SUPER_SECRET'),
        expiresIn: jwtRefreshExp,
      });

      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens')
        .send({ refreshToken: rt });

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);

      // db checks

      const userRefreshTokens = await prismaService.refreshToken.findMany({
        where: { userId: userFixture.user.id },
      });

      expectAllRevoked(userRefreshTokens);
    });
    it('should return 401 Unauthorized and revoke all user tokens if refresh token is not valid', async () => {
      const payload = { id: uuidv4(), sub: userFixture.user.id };
      const rt = jwtService.sign(payload, {
        secret: 'wrongSecret',
        expiresIn: jwtRefreshExp,
      });

      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens')
        .send({ refreshToken: rt });

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);

      // db checks

      const userRefreshTokens = await prismaService.refreshToken.findMany({
        where: { userId: userFixture.user.id },
      });

      expectAllRevoked(userRefreshTokens);
    });
    it('should return 401 Unauthorized if user not in db', async () => {
      const payload = { id: uuidv4(), sub: 999 };
      const rt = jwtService.sign(payload, {
        secret: getEnvVar('JWT_SUPER_SECRET'),
        expiresIn: jwtRefreshExp,
      });
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens/')
        .send({ refreshToken: rt });

      expect(res.status).toBe(401);
    });

    it('should return 400 BadRequest if body contain unexpected/extra properties', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens/')
        .send({ refreshToken, extra: 'extra' });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if refreshToken is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens/')
        .send({ refreshToken: '' });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if refreshToken is not string', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens/')
        .send({ refreshToken: 1 });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if body is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/auth/refresh-tokens/')
        .send({});

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
  });
});
