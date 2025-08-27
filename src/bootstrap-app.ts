import { INestApplication, ValidationPipe } from '@nestjs/common';
import { getEnvVar } from './common/functions';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

export async function setupApp(app: INestApplication) {
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
      forbidUnknownValues: true,
    }),
  );
  app.enableCors({
    origin: getEnvVar('CORS_ORIGIN'),
    credentials: true,
  });
  app.useGlobalFilters(new HttpExceptionFilter());

  await app.init();
  return app;
}
