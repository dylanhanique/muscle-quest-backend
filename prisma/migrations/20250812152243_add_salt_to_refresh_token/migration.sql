/*
  Warnings:

  - Added the required column `salt` to the `RefreshToken` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "RefreshToken" ADD COLUMN     "salt" TEXT NOT NULL;
