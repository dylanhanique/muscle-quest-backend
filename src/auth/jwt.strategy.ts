import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import {
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtPayload } from './types/auth.types';
import { UsersService } from '../users/users.service';
import { getEnvVar } from '../common/functions';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly userService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: getEnvVar('JWT_SECRET'),
    });
  }

  private readonly logger = new Logger(JwtStrategy.name);

  async validate(payload: JwtPayload) {
    try {
      const user = await this.userService.findOneById(payload.sub);

      if (!user) {
        throw new UnauthorizedException();
      }

      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error('Unexpected error in JWT validation:', error);
      throw new InternalServerErrorException();
    }
  }
}
