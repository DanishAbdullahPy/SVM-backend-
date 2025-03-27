/*
  Warnings:

  - The `shiprocketOrderId` column on the `Order` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - The `shiprocketShipmentId` column on the `Order` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- AlterTable
ALTER TABLE "Order" DROP COLUMN "shiprocketOrderId",
ADD COLUMN     "shiprocketOrderId" INTEGER,
DROP COLUMN "shiprocketShipmentId",
ADD COLUMN     "shiprocketShipmentId" INTEGER;
