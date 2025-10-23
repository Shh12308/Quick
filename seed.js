import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();
const prisma = new PrismaClient();

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL || "admin@zenstream.local";
  const existing = await prisma.user.findUnique({ where: { email } });

  if (existing) {
    console.log("Superadmin already exists:", existing.email);
    return;
  }

  const passwordHash = await bcrypt.hash(process.env.SEED_ADMIN_PASSWORD || "adminpass", 10);

  const user = await prisma.user.create({
    data: {
      name: "Super Admin",
      email,
      password: passwordHash,
      role: "admin",
      subscriptionType: "premium",
      subscriptionActive: true,
    },
  });

  console.log("Created superadmin:", user.email);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(() => process.exit(0));
