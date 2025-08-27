import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { AppController } from './app.controlller';
import { RefreshTokenModule } from './refresh-token/refresh-token.module';
import { WorkoutModule } from './workout/workout.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: [`.env.${process.env.NODE_ENV}`],
    }),
    AuthModule,
    UsersModule,
    RefreshTokenModule,
    WorkoutModule,
  ],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
