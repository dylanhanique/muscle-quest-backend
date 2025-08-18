import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Workout } from '../../generated/prisma';

@Injectable()
export class WorkoutService {
  constructor(private readonly prisma: PrismaService) {}

  async create(userId: number, name: string): Promise<Workout> {
    try {
      return await this.prisma.workout.create({ data: { userId, name } });
    } catch (error) {
      throw new InternalServerErrorException(
        'An unexpected error occured during workout creation',
      );
    }
  }

  async findOneById(id: number, userId: number): Promise<Workout | null> {
    try {
      return await this.prisma.workout.findUnique({ where: { id, userId } });
    } catch (error) {
      throw new InternalServerErrorException(
        'An unexpected error occured during finding workout by id',
      );
    }
  }

  async findByUserId(userId: number): Promise<Workout[]> {
    try {
      return await this.prisma.workout.findMany({ where: { userId } });
    } catch (error) {
      throw new InternalServerErrorException(
        'An unexpected error occured during finding all workouts',
      );
    }
  }

  async updateName(id: number, userId: number, name: string): Promise<Workout> {
    try {
      const workout = await this.prisma.workout.findUnique({
        where: { id, userId },
      });

      if (!workout) {
        throw new NotFoundException();
      }

      return await this.prisma.workout.update({
        where: { id, userId },
        data: {
          name,
        },
      });
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      } else {
        throw new InternalServerErrorException(
          'An unexpected error occured during finding all workouts',
        );
      }
    }
  }

  async delete(id: number, userId: number): Promise<void> {
    try {
      const workout = await this.prisma.workout.findUnique({
        where: { id, userId },
      });
      if (!workout) {
        throw new NotFoundException();
      }

      await this.prisma.workout.delete({ where: { id, userId } });
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      } else {
        throw new InternalServerErrorException();
      }
    }
  }
}
