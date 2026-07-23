const pidFile = process.argv[2];
const markerFile = process.argv[3];
if (pidFile === undefined || markerFile === undefined) throw new Error("Missing descendant witness files");
const marker = (await Bun.file(markerFile).text()).trim();
if (marker.length === 0) throw new Error("Missing descendant marker");

const descendant = Bun.spawn([
  process.execPath,
  "-e",
  `const grandchild = Bun.spawn([
    process.execPath,
    "-e",
    ${JSON.stringify(`
      import { writeFileSync } from "node:fs";
      writeFileSync(${JSON.stringify(pidFile)}, process.pid + "\\n", { encoding: "utf8", mode: 0o600 });
      setInterval(() => process.stdout.write("held\\n"), 10);
    `)},
    ${JSON.stringify(marker)}
  ], { detached: true, stdout: "inherit", stderr: "inherit" });
  grandchild.unref();`,
], {
  detached: true,
  stdout: "inherit",
  stderr: "inherit",
});

descendant.unref();
setInterval(() => {}, 1_000);
