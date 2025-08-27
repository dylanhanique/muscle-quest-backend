import { Test, TestingModule } from '@nestjs/testing';
import { WorkoutService } from '../workout.service';
import { PrismaService } from '../../prisma/prisma.service';
import { Workout } from 'generated/prisma';
import { PrismaClientUnknownRequestError } from '../../../generated/prisma/runtime/library';
import {
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { CreateWorkoutDto, UpdateWorkoutNameDto } from '../dto/workout.dto';

let prismaServiceMock: {
  workout: {
    create: jest.Mock;
    findUnique: jest.Mock;
    findMany: jest.Mock;
    update: jest.Mock;
    delete: jest.Mock;
  };
};

describe('WorkoutService', () => {
  let service: WorkoutService;
  const workoutMock: Workout = {
    id: 1,
    name: 'Workout',
    userId: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();

    prismaServiceMock = {
      workout: {
        create: jest.fn(),
        findUnique: jest.fn(),
        findMany: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WorkoutService,
        { provide: PrismaService, useValue: prismaServiceMock },
      ],
    }).compile();

    service = module.get<WorkoutService>(WorkoutService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    const createWorkoutDto: CreateWorkoutDto = {
      name: workoutMock.name,
    };

    it('should return the newly created workout', async () => {
      prismaServiceMock.workout.create.mockResolvedValue(workoutMock);

      expect(
        await service.create(workoutMock.userId, createWorkoutDto),
      ).toEqual(workoutMock);
      expect(prismaServiceMock.workout.create).toHaveBeenCalledWith({
        data: { userId: workoutMock.userId, name: workoutMock.name },
      });
    });

    it('should return an InternalServerErrorException if an error occurs', async () => {
      prismaServiceMock.workout.create.mockRejectedValue(
        new PrismaClientUnknownRequestError('error', {
          clientVersion: 'x.y.z',
        }),
      );
      await expect(
        service.create(workoutMock.id, createWorkoutDto),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findOneById', () => {
    it('should return a workout if the id exists', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(workoutMock);

      expect(
        await service.findOneById(workoutMock.id, workoutMock.userId),
      ).toEqual(workoutMock);
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
    });

    it('should return null if the workout is not found', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(null);

      expect(
        await service.findOneById(workoutMock.id, workoutMock.userId),
      ).toEqual(null);
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
    });

    it('should return an InternalServerErrorException if an error occurs', async () => {
      prismaServiceMock.workout.findUnique.mockRejectedValue(
        new PrismaClientUnknownRequestError('error', {
          clientVersion: 'x.y.z',
        }),
      );

      await expect(
        service.findOneById(workoutMock.id, workoutMock.userId),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('findByUserId', () => {
    it('should return all workouts if user has any', async () => {
      prismaServiceMock.workout.findMany.mockResolvedValue([workoutMock]);

      expect(await service.findByUserId(workoutMock.userId)).toEqual([
        workoutMock,
      ]);
      expect(prismaServiceMock.workout.findMany).toHaveBeenCalledWith({
        where: { userId: workoutMock.userId },
      });
    });

    it('should return an empty array if the user has no workouts', async () => {
      prismaServiceMock.workout.findMany.mockResolvedValue([]);

      expect(await service.findByUserId(workoutMock.userId)).toEqual([]);
      expect(prismaServiceMock.workout.findMany).toHaveBeenCalledWith({
        where: { userId: workoutMock.userId },
      });
    });

    it('should return an InternalServerErrorException if an error occurs', async () => {
      prismaServiceMock.workout.findMany.mockRejectedValue(
        new PrismaClientUnknownRequestError('error', {
          clientVersion: 'x.y.z',
        }),
      );
      await expect(service.findByUserId(workoutMock.id)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('updateName', () => {
    const updateMockResult = { ...workoutMock, name: 'NewName' };
    const updateWorkoutNameDto: UpdateWorkoutNameDto = {
      name: updateMockResult.name,
    };

    it('should update name and return workout if id and userId is correct', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(workoutMock);
      prismaServiceMock.workout.update.mockResolvedValue(updateMockResult);

      expect(
        await service.updateName(
          workoutMock.id,
          workoutMock.userId,
          updateWorkoutNameDto,
        ),
      ).toEqual(updateMockResult);
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
      expect(prismaServiceMock.workout.update).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
        data: { name: updateMockResult.name },
      });
    });

    it('should return a NotFoundException if the workout is not found', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(null);

      await expect(
        service.updateName(
          workoutMock.id,
          workoutMock.userId,
          updateWorkoutNameDto,
        ),
      ).rejects.toThrow(NotFoundException);
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
    });

    it('should return an InternalServerErrorException for other errors', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(workoutMock);
      prismaServiceMock.workout.update.mockRejectedValue(
        new PrismaClientUnknownRequestError('error', {
          clientVersion: 'x.y.z',
        }),
      );

      await expect(
        service.updateName(
          workoutMock.id,
          workoutMock.userId,
          updateWorkoutNameDto,
        ),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });

  describe('delete', () => {
    it('should delete the workout if id and userId is correct', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(workoutMock);
      prismaServiceMock.workout.delete.mockResolvedValue(null);

      expect(await service.delete(workoutMock.id, workoutMock.userId)).toEqual(
        undefined,
      );
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
      expect(prismaServiceMock.workout.delete).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
    });

    it('should throw a NotFoundException if the workout is not found', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(null);

      await expect(
        service.delete(workoutMock.id, workoutMock.userId),
      ).rejects.toThrow(NotFoundException);
      expect(prismaServiceMock.workout.findUnique).toHaveBeenCalledWith({
        where: { id: workoutMock.id, userId: workoutMock.userId },
      });
    });

    it('should throw an InternalServerErrorException for other errors', async () => {
      prismaServiceMock.workout.findUnique.mockResolvedValue(workoutMock);
      prismaServiceMock.workout.delete.mockRejectedValue(
        new PrismaClientUnknownRequestError('error', {
          clientVersion: 'x.y.z',
        }),
      );

      await expect(
        service.delete(workoutMock.id, workoutMock.userId),
      ).rejects.toThrow(InternalServerErrorException);
    });
  });
});
