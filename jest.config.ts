import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/src/**/*.spec.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.json' }],
  },
  collectCoverage: false,
  collectCoverageFrom: ['**/*.{ts, js}', '!**/node_modules/**'],
  coverageDirectory: '../coverage',
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
  verbose: true,
};

export default config;
