import { Controller, Request, Post, UseGuards, Body } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/auth.dto';
import { AuthenticatedUser } from './types/auth.types';
import { LoginValidationGuard } from './guard/login-validation.guard';
import { RefreshTokenDto } from '../refresh-token/dto/refresh-token.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(LoginValidationGuard, AuthGuard('local'))
  @Post('login')
  async login(
    @Body() loginCredentials: LoginDto, // validation only, not used in the logic
    @Request() req: { user: AuthenticatedUser },
  ) {
    return await this.authService.login(req.user);
  }

  @Post('refresh-tokens')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return await this.authService.refreshTokens(refreshTokenDto.refreshToken);
  }
}
