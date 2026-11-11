import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
async function files(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await files(path)));
    else if (entry.isFile()) result.push(path);
    else throw new Error(`Unexpected non-regular distribution entry: ${path}`);
  }
  return result;
}

/** Every source module produces one JavaScript module and one declaration, with no stale extras. */
export async function checkDistribution(
  root = packageRoot,
  output = join(root, "dist"),
) {
  const manifest = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  const source = join(root, "src");
  const expected = (await files(source))
    .flatMap((path) => {
      if (!/\.(ts|js)$/.test(path) || path.endsWith(".d.ts"))
        throw new Error(`Unsupported source file: ${path}`);
      const stem = relative(source, path)
        .replace(/\.(ts|js)$/, "")
        .split(sep)
        .join("/");
      return [`${stem}.js`, `${stem}.d.ts`];
    })
    .sort();
  const actual = (await files(output))
    .map((path) => relative(output, path).split(sep).join("/"))
    .sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    const missing = expected.filter((path) => !actual.includes(path));
    const extra = actual.filter((path) => !expected.includes(path));
    throw new Error(
      `Distribution differs from source modules: missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)}`,
    );
  }
  for (const [name, entry] of Object.entries(manifest.exports)) {
    for (const condition of ["types", "import"]) {
      const path = entry[condition];
      if (
        typeof path !== "string" ||
        !path.startsWith("./dist/") ||
        !actual.includes(path.slice(7))
      ) {
        throw new Error(`Missing ${condition} export ${name}: ${path}`);
      }
    }
  }
  return { files: actual.length, exports: Object.keys(manifest.exports) };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  console.log(JSON.stringify(await checkDistribution()));
}
