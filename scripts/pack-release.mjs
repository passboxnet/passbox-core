// Packs every @passbox/* package into dist/ for a GitHub release, with a
// SHA256SUMS file. pnpm pack replaces workspace:* with the released version.
// Until the packages are on npm, other repositories install these tarballs
// by URL, e.g. https://github.com/passboxnet/core/releases/download/v0.1.0/passbox-ui-0.1.0.tgz
//
//   pnpm build:wasm && node scripts/pack-release.mjs

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);

const dirs = [
  ...readdirSync(join(root, "packages")).map((d) => join(root, "packages", d)),
  join(root, "crates/core-wasm"),
];
for (const dir of dirs) {
  execFileSync("pnpm", ["pack", "--pack-destination", dist], { cwd: dir, stdio: "inherit" });
}

const sums = readdirSync(dist)
  .filter((f) => f.endsWith(".tgz"))
  .sort()
  .map(
    (f) =>
      `${createHash("sha256")
        .update(readFileSync(join(dist, f)))
        .digest("hex")}  ${f}`,
  );
writeFileSync(join(dist, "SHA256SUMS"), `${sums.join("\n")}\n`);
console.log(sums.join("\n"));
