import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Workout } from '../../generated/prisma';
import { CreateWorkoutDto, UpdateWorkoutNameDto } from './dto/workout.dto';

@Injectable()
export class WorkoutService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    userId: number,
    createWorkoutDto: CreateWorkoutDto,
  ): Promise<Workout> {
    try {
      return await this.prisma.workout.create({
        data: { userId, ...createWorkoutDto },
      });
    } catch (error) {
      throw new InternalServerErrorException(
        'An unexpected error occured during workout creation',
      );
    }
  }

  async findOneById(id: number, userId: number): Promise<Workout | null> {
    try {
      return await this.prisma.workout.findUnique({
        where: { id, userId },
      });
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

  async updateName(
    id: number,
    userId: number,
    updateWorkoutNameDto: UpdateWorkoutNameDto,
  ): Promise<Workout> {
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
          name: updateWorkoutNameDto.name,
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
