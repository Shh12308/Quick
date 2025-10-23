datasource db {
  provider = "mongodb"  // or "postgresql" if you prefer SQL
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

model User {
  id                String   @id @map("_id") @default(auto()) @db.ObjectId
  googleId          String?  @unique
  name              String
  email             String   @unique
  password          String?
  role              String   @default("user")
  subscriptionType  String   @default("free")
  subscriptionActive Boolean  @default(false)
  subscriptionEnd   DateTime?
  strikes           Int      @default(0)
  lastLogin         DateTime @default(now())
  createdAt         DateTime @default(now())
}
