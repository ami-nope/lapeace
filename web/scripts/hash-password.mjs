import { randomBytes, scryptSync } from "node:crypto";
import { readFileSync } from "node:fs";

const password = readFileSync(0, "utf8").replace(/[\r\n]+$/, "");
if (password.length < 12) {
  console.error("Use a passphrase of at least 12 characters.");
  process.exit(1);
}

const salt = randomBytes(16);
const digest = scryptSync(password, salt, 64);
console.log(`scrypt:${salt.toString("hex")}:${digest.toString("hex")}`);
