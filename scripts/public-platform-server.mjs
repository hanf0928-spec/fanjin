#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const data = path.resolve(process.env.FANJIN_DATA_DIR || path.join(root, ".fanjin-data"));
fs.mkdirSync(data, { recursive: true, mode: 0o700 });
const bootstrap = path.join(data, "bootstrap.json");
let password = process.env.FANJIN_ROOT_PASSWORD;
if (!password) {
  if (!fs.existsSync(bootstrap)) fs.writeFileSync(bootstrap, JSON.stringify({ username: "root", password: crypto.randomBytes(24).toString("base64url") }, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  password = JSON.parse(fs.readFileSync(bootstrap, "utf8")).password;
  process.stdout.write("Local first-login credentials: .fanjin-data/bootstrap.json (or your explicit FANJIN_DATA_DIR). Change the password after login.\n");
}
if (typeof password !== "string" || password.length < 16) throw Error("Local root password must be at least 16 characters");
// Only explicit storage settings (plus the two opt-in flags below) are
// forwarded, never the ambient environment.
const storageNames = ["PROVIDER", "DRIVER", "BUCKET", "REGION", "ENDPOINT", "CDN_URL", "ACCESS_KEY", "SECRET_KEY", "CORS_ORIGINS", "URL_MODE", "KEY_PREFIX", "FORCE_PATH_STYLE", "SIGNED_URL_TTL_SECONDS"].map(name => `FANJIN_OBJECT_STORAGE_${name}`);
const storageEnvironment = Object.fromEntries([...storageNames, "NODE_EXTRA_CA_CERTS"].filter(name => process.env[name]).map(name => [name, process.env[name]]));
// Operator opt-in only: unset by default, deployer must explicitly set
// FANJIN_ENABLE_AUTO_LOGIN=1 for the credential-free admin session route to
// respond (see src/routes/auth/auto-login.ts). Never forwarded implicitly.
const autoLoginEnvironment = process.env.FANJIN_ENABLE_AUTO_LOGIN
  ? { FANJIN_ENABLE_AUTO_LOGIN: process.env.FANJIN_ENABLE_AUTO_LOGIN }
  : {};
const child = spawn(process.execPath, ["build-public/app.cjs"], {
  cwd: path.join(root, "fanjin-new/fanjin-api"), stdio: "inherit",
  env: {
    ...storageEnvironment,
    ...autoLoginEnvironment,
    PATH: process.env.PATH || "", NODE_ENV: "development", FANJIN_PROCESS_ROLE: "all",
    FANJIN_DISABLE_LOCAL_ENV: "1", FANJIN_DISABLE_LOCAL_KEYCHAIN_SECRETS: "1",
    FANJIN_DATA_DIR: data, FANJIN_DATABASE_CLIENT: "sqlite", FANJIN_AUTO_MIGRATE: "1",
    FANJIN_ROOT_PASSWORD: password,
    FANJIN_BIND_HOST: process.env.FANJIN_BIND_HOST || "127.0.0.1", FANJIN_APP_PORT: process.env.FANJIN_APP_PORT || "19692",
    FANJIN_WEB_DIR: path.join(root, "fanjin-new/fanjin-v4/dist"), FANJIN_DISABLE_BACKUP_SCHEDULER: "1",
  },
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
child.on("exit", code => { process.exitCode = code || 0; });
