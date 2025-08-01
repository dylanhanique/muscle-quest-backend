import {
  Controller,
  Request,
  Post,
  UseGuards,
  Body,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth/auth.service';
import { LoginDto } from './auth/dto/login.dto';
import { AuthenticatedUser } from './auth/types/auth.types';

@Controller()
export class AppController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(AuthGuard('local'))
  @UsePipes(new ValidationPipe())
  @Post('auth/login')
  async login(
    @Body() loginCredentials: LoginDto, // validation only, not used in the logic
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.authService.login(req.user);
  }

  @UsePipes(new ValidationPipe())
  @Post('auth/refresh-token')
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    console.log(refreshToken);
    return await this.authService.refreshAccessToken(refreshToken);
  }
}
