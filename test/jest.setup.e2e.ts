import * as dotenv from 'dotenv';
import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';
import * as request from 'supertest';
import { Server } from 'http';
import { PrismaService } from '../src/prisma/prisma.service';
import { setupApp } from '../src/bootstrap-app';
import { TestUtils } from './test-utils';
import { JwtService } from '@nestjs/jwt';

dotenv.config({
  path: `.env.${process.env.NODE_ENV}`,
});

let app: INestApplication;
let httpServer: Server;
let testUtils: TestUtils;
let jwtService: JwtService;
let prismaService: PrismaService;

beforeAll(async () => {
  const moduleRef: TestingModule = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  app = moduleRef.createNestApplication();
  await setupApp(app);

  prismaService = app.get(PrismaService);
  jwtService = app.get(JwtService);
  testUtils = new TestUtils(prismaService, jwtService);

  httpServer = app.getHttpServer() as Server;
});

it('app should be defined', () => {
  expect(app).toBeDefined();
});

afterAll(async () => {
  await app.close();
});

export { app, httpServer, request, testUtils, prismaService, jwtService };
