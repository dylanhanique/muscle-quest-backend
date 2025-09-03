ARG NODE_VERSION=22.17.0

FROM node:${NODE_VERSION}-alpine AS base

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npx prisma generate


# Dev stage
FROM base AS development

CMD ["npm", "run", "start:dev"]


# Test stage
FROM base AS test

CMD ["npm", "run", "test:e2e"]


# Build stage
FROM base AS build

RUN npm run build


# Production stage
FROM node:22-alpine AS production

WORKDIR /app

COPY package*.json ./

RUN npm install --omit=dev

COPY --from=build /app/dist ./dist
COPY --from=base /app/generated ./generated
COPY --from=base /app/prisma ./prisma

EXPOSE 3000
CMD ["npm", "run", "start:prod"]