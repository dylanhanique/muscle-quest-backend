import {
  CanActivate,
  ExecutionContext,
  BadRequestException,
  Injectable,
} from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validateSync } from 'class-validator';
import { LoginDto } from '../dto/auth.dto';
import { Request } from 'express';

@Injectable()
export class LoginValidationGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req: Request = context.switchToHttp().getRequest();
    const dto = plainToInstance(LoginDto, req.body);
    const errors = validateSync(dto);

    if (errors.length > 0) {
      throw new BadRequestException(errors);
    }
    return true;
  }
}
