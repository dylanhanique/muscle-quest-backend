import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Put,
  Request,
  UseGuards,
} from '@nestjs/common';
import { WorkoutService } from './workout.service';
import { AuthGuard } from '@nestjs/passport';
import { CreateWorkoutDto, UpdateWorkoutNameDto } from './dto/workout.dto';
import { AuthenticatedUser } from '../auth/types/auth.types';

@Controller('workout')
export class WorkoutController {
  constructor(private readonly workoutService: WorkoutService) {}

  @UseGuards(AuthGuard('jwt'))
  @Post()
  async create(
    @Body() createWorkoutDto: CreateWorkoutDto,
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.workoutService.create(req.user.id, createWorkoutDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('findByUserId')
  async findByUserId(@Request() req: { user: AuthenticatedUser }) {
    return await this.workoutService.findByUserId(req.user.id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get(':id')
  async findOneById(
    @Param('id') id: number,
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.workoutService.findOneById(id, req.user.id);
  }

  @UseGuards(AuthGuard('jwt'))
  @Put(':id')
  async updateName(
    @Param('id') id: number,
    @Body() updateWorkoutNameDto: UpdateWorkoutNameDto,
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.workoutService.updateName(
      id,
      req.user.id,
      updateWorkoutNameDto,
    );
  }

  @UseGuards(AuthGuard('jwt'))
  @Delete(':id')
  async delete(
    @Param('id') id: number,
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.workoutService.delete(id, req.user.id);
  }
}
