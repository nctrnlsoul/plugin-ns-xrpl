#!/usr/bin/env bun
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { $ } from "bun";

const RM_RECURSIVE_SCRIPT = fileURLToPath(
	new URL("./scripts/rm-path-recursive.mjs", import.meta.url),
);

function rmRecursive(target: string) {
	const result = spawnSync(process.execPath, [RM_RECURSIVE_SCRIPT, target], {
		stdio: "inherit",
	});
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(
			`rm-path-recursive failed for ${target} with status ${result.status}`,
		);
	}
}

async function cleanBuild(outdir = "dist") {
	if (existsSync(outdir)) {
		rmRecursive(outdir);
		console.log(`✓ Cleaned ${outdir} directory`);
	}
}

async function build() {
	const start = performance.now();
	console.log("🚀 Building plugin...");

	try {
		await cleanBuild("dist");

		// Both halves are checked below. The scaffold destructured only the
		// first, so a failed declaration build was discarded and the script
		// still printed "Build complete!" over a package with no types in it.
		const [buildResult, typesResult] = await Promise.all([
			(async () => {
				console.log("📦 Bundling with Bun...");
				const result = await Bun.build({
					entrypoints: ["./src/index.ts"],
					outdir: "./dist",
					target: "node",
					format: "esm",
					sourcemap: true,
					minify: false,
					external: ["dotenv", "node:*", "@elizaos/core", "zod"],
					naming: {
						entry: "[dir]/[name].[ext]",
					},
				});

				if (!result.success) {
					console.error("✗ Build failed:", result.logs);
					return { success: false, outputs: [] };
				}

				const totalSize = result.outputs.reduce(
					(sum, output) => sum + output.size,
					0,
				);
				const sizeMB = (totalSize / 1024 / 1024).toFixed(2);
				console.log(`✓ Built ${result.outputs.length} file(s) - ${sizeMB}MB`);

				return result;
			})(),

			(async () => {
				console.log("📝 Generating TypeScript declarations...");
				// Run TypeScript's own JS entry point through node.
				//
				// Three things this avoids, each of which actually happened.
				// Resolving bare `tsc` from PATH failed when
				// checks/package_entries.ts invoked this build as a subprocess,
				// because a spawned process does not necessarily inherit
				// node_modules/.bin. Pointing at node_modules/.bin/tsc then
				// failed because Bun's shell cannot execute a Windows .cmd shim.
				// Pointing at typescript/bin/tsc failed too: it is extensionless
				// and the runtime would not resolve it as a module. lib/tsc.js
				// has none of those problems under either runtime.
				//
				// --incremental is deliberately NOT passed: the flag overrides
				// tsconfig.build.json and re-creates the .tsbuildinfo that was
				// shipping as 152.9 kB of build metadata inside the tarball.
				const tscEntry = fileURLToPath(
					new URL("./node_modules/typescript/lib/tsc.js", import.meta.url),
				);
				const tscRun = spawnSync(
					process.execPath,
					[tscEntry, "--emitDeclarationOnly", "--project", "./tsconfig.build.json"],
					{ stdio: "pipe", encoding: "utf8" },
				);
				if (tscRun.status !== 0) {
					console.error("✗ TypeScript declarations failed:");
					console.error(`${tscRun.stdout ?? ""}${tscRun.stderr ?? ""}`.trim());
					return { success: false };
				}
				console.log("✓ TypeScript declarations generated");
				return { success: true };
			})(),
		]);

		if (!buildResult.success || !typesResult.success) {
			return false;
		}

		const elapsed = ((performance.now() - start) / 1000).toFixed(2);
		console.log(`✅ Build complete! (${elapsed}s)`);
		return true;
	} catch (error) {
		console.error("Build error:", error);
		return false;
	}
}

build()
	.then((success) => {
		if (!success) {
			process.exit(1);
		}
	})
	.catch((error) => {
		console.error("Build script error:", error);
		process.exit(1);
	});
