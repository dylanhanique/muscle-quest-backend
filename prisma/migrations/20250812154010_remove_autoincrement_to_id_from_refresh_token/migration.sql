-- AlterTable
ALTER TABLE "RefreshToken" ALTER COLUMN "id" DROP DEFAULT;
DROP SEQUENCE "RefreshToken_id_seq";
