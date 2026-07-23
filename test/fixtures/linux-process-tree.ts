import { realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, relative, sep } from "node:path";

interface CapturedChild {
  readonly pid: number;
  kill(signal?: NodeJS.Signals | number): void;
}

interface LinuxPidNamespaceSpawnOptions {
  readonly cwd: string;
  readonly detached: true;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly stderr: "pipe";
  readonly stdout: "pipe";
  readonly writableRoots: readonly string[];
}

const resolvedBwrap = Bun.which("bwrap");
if (resolvedBwrap === null) throw new Error("Atomic interruption tests require bubblewrap PID namespaces");
const BWRAP: string = resolvedBwrap;

export function spawnInLinuxPidNamespace(
  command: readonly string[],
  options: LinuxPidNamespaceSpawnOptions,
) {
  const canonicalTempRoot = realpathSync(tmpdir());
  const canonicalPrivateTempRoot = realpathSync("/tmp");
  const canonicalCwd = realpathSync(options.cwd);
  const relativeCwd = relative(canonicalPrivateTempRoot, canonicalCwd);
  const cwdUnderPrivateTemp = relativeCwd.length > 0 && isWithinOrSame(relativeCwd);
  const writableRoots = [...new Set(options.writableRoots)].map((root) => {
    if (root.includes("\0")) {
      throw new Error(`Atomic interruption writable root must be an explicit /tmp child: ${root}`);
    }
    const canonicalRoot = realpathSync(root);
    const relativeRoot = relative(canonicalTempRoot, canonicalRoot);
    const overlapsCwd = isWithinOrSame(relative(canonicalCwd, canonicalRoot))
      || isWithinOrSame(relative(canonicalRoot, canonicalCwd));
    if (root !== canonicalRoot || relativeRoot.length === 0 || !isWithinOrSame(relativeRoot)
      || overlapsCwd) {
      throw new Error(`Atomic interruption writable root must be a canonical /tmp child: ${root}`);
    }
    return canonicalRoot;
  });
  const readOnlyCwdBind = cwdUnderPrivateTemp
    ? ["--ro-bind", canonicalCwd, canonicalCwd]
    : [];
  const tempBinds = writableRoots.flatMap((root) => ["--bind", root, root]);
  const { writableRoots: _, cwd: __, ...spawnOptions } = options;
  return Bun.spawn([
    BWRAP,
    "--unshare-pid",
    "--die-with-parent",
    "--ro-bind", "/", "/",
    "--tmpfs", "/tmp",
    ...readOnlyCwdBind,
    ...tempBinds,
    "--proc", "/proc",
    "--dev-bind", "/dev", "/dev",
    "--",
    ...command,
  ], { ...spawnOptions, cwd: canonicalCwd });
}

function isWithinOrSame(relativePath: string): boolean {
  return relativePath !== ".." && !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath);
}

export function killLinuxProcessTree(child: CapturedChild): void {
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    if (!isNoSuchProcess(error)) throw error;
  }
  try {
    child.kill("SIGKILL");
  } catch (error) {
    if (!isNoSuchProcess(error)) throw error;
  }
}

function isNoSuchProcess(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH";
}
