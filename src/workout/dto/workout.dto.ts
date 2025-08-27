import { PickType } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateWorkoutDto {
  @IsString()
  @IsNotEmpty()
  name: string;
}

export class UpdateWorkoutNameDto extends PickType(CreateWorkoutDto, [
  'name',
] as const) {}
