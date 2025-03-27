-- AlterTable
ALTER TABLE "Product" ADD COLUMN     "discount" DOUBLE PRECISION,
ADD COLUMN     "discountExpiry" TIMESTAMP(3),
ADD COLUMN     "featured" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "limitedOffer" BOOLEAN NOT NULL DEFAULT false;
