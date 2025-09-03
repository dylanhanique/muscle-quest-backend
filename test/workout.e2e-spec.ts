import { faker } from '@faker-js/faker';
import { CreateWorkoutDto } from '../src/workout/dto/workout.dto';
import {
  httpServer,
  prismaService,
  request,
  testUtils,
} from './jest.setup.e2e';
import { UserTestFixture } from './types/test-types';
import { Workout } from '../generated/prisma';
import { HttpStatus } from '@nestjs/common';

describe('Workout e2e', () => {
  describe('create', () => {
    const dto: CreateWorkoutDto = {
      name: faker.word.words(3),
    };

    let userFixture: UserTestFixture;
    let jwtFixture: string;

    beforeEach(async () => {
      userFixture = await testUtils.createUserTestFixture();
      jwtFixture = testUtils.createJwt(
        userFixture.user.id,
        userFixture.user.username,
      );
    });

    it('should return the created workout', async () => {
      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${jwtFixture}`)
        .send(dto);

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('id');
      expect(res.body).toMatchObject({
        userId: userFixture.user.id,
        name: dto.name,
      });

      const storedWorkout: Workout | null =
        await prismaService.workout.findUnique({
          where: { id: res.body.id, userId: res.body.userId },
        });

      expect(storedWorkout).not.toBeNull();
      expect(storedWorkout!.name).toBe(res.body.name);
    });

    it('should return 401 Unauthorized if jwt sub is not found', async () => {
      const fakeSubJwt = testUtils.createJwt(999, faker.internet.username());

      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${fakeSubJwt}`)
        .send(dto);

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);
    });
    it('should return 401 Unauthorized if jwt is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ''`)
        .send(dto);

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);
    });
    it('should return 401 Unauthorized if jwt is not valid', async () => {
      const fakeJwt = faker.internet.jwt();

      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${fakeJwt}`)
        .send(dto);

      expect(res.status).toBe(HttpStatus.UNAUTHORIZED);
    });

    it('should return 400 BadRequest if name is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${jwtFixture}`)
        .send({ name: '' });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if name is not a string', async () => {
      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${jwtFixture}`)
        .send({ name: 1 });

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
    it('should return 400 BadRequest if body is empty', async () => {
      const res: request.Response = await request(httpServer)
        .post('/workout')
        .set('Authorization', `Bearer ${jwtFixture}`)
        .send({});

      expect(res.status).toBe(HttpStatus.BAD_REQUEST);
    });
  });
});
