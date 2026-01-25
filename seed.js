// prisma/seed.js

const { PrismaClient } = require("@prisma/client");
const { argon2 } = require("argon2"); // 1. Import argon2
require("dotenv").config();

const prisma = new PrismaClient();

async function main() {
  const email = process.env.SEED_ADMIN_EMAIL || "admin@zenstream.local";
  const existing = await prisma.user.findUnique({ where: { email } });

  if (existing) {
    console.log("Superadmin already exists:", existing.email);
    return;
  }

  // 2. Hash the password using argon2.hash()
  // Argon2 automatically handles salt generation and is much more secure.
  const passwordHash = await argon2.hash(process.env.SEED_ADMIN_PASSWORD || "adminpass");

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
