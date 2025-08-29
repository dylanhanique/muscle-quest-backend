ARG NODE_VERSION=22.17.0

FROM node:${NODE_VERSION}-alpine AS base

WORKDIR /app/backend

COPY package*.json ./

RUN npm install

COPY prisma ./prisma
RUN npx prisma generate

COPY . .

## Dev stage

FROM base AS development

CMD ["npm", "run", "start:dev"]

## Test stage

FROM base AS test
ENV NODE_ENV=test

CMD ["npm", "run", "test:e2e"]

# Build stage
FROM base AS build

RUN npm run build

## Build production
FROM node:22-alpine AS production

WORKDIR /app/backend

COPY package*.json ./

RUN npm install --omit=dev

COPY --from=build /app/backend/dist ./dist
COPY --from=base /app/backend/prisma ./prisma

EXPOSE 3000
CMD ["npm", "run", "start:prod"]