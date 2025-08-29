import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { getEnvVar } from './common/functions';
import { setupApp } from './bootstrap-app';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await setupApp(app);

  app.enableCors({
    origin: getEnvVar('CORS_ORIGIN'),
    credentials: true,
  });

  const config = new DocumentBuilder()
    .setTitle('MuscleQuest Backend')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('swagger', app, document);

  const logger = new Logger('Bootstrap');
  await app.listen(getEnvVar('PORT'));
  logger.log('Application is running 🚀');
}

bootstrap();
