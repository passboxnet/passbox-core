// Builds the WebAssembly package into ./pkg using cargo and wasm-bindgen-cli.
// The wasm-bindgen-cli version must match the wasm-bindgen crate in Cargo.lock.
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const run = (cmd, args) => execFileSync(cmd, args, { cwd: root, stdio: "inherit" });

run("cargo", ["build", "--package", "passbox-core-wasm", "--target", "wasm32-unknown-unknown", "--release"]);
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  join(here, "pkg"),
  join(root, "target", "wasm32-unknown-unknown", "release", "passbox_core_wasm.wasm"),
]);
