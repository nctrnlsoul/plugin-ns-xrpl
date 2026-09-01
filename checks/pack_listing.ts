// The pure half of the package check: given an `npm pack --dry-run` listing,
// say what is in it that must not ship.
//
// Pure and exported deliberately, per rule 42. The logic used to sit inline in
// checks/package_entries.ts BELOW a `bun run build`, and build.ts deletes dist
// before emitting into it. So the guard cleaned its own subject before measuring
// it and could not fail on the one input it was written for: it printed
//
//     package entries: no frontend, no build metadata, nothing secret-shaped
//
// with exit code 0, against the exact tree where `npm pack --dry-run` listed
// 163.4 kB of dist/tsconfig.tsbuildinfo, 57% of the unpacked package.
//
// A guard placed downstream of a clean is not a guard, for the same reason a
// guard placed downstream of a coercion is not one. Splitting the decision out
// here means it can be called on the tree AS HANDED, and can be tested without
// running a build at all.

/** The deleted frontend organism. Rule 85: dead code answers audits for live code. */
export const BANNED_FRONTEND: readonly string[] = [
  "react",
  "vite",
  "tailwind",
  "postcss",
  "frontend",
  "index.html",
  "tanstack",
];

/** Build metadata is not a deliverable. */
export const BANNED_BUILD_METADATA: readonly string[] = ["tsbuildinfo", ".env", "node_modules"];

/** Nothing that could carry a secret. */
export const BANNED_SECRETISH: readonly string[] = [".npmrc", "id_rsa", ".pem", ".key"];

/**
 * Escape EVERY regex metacharacter, not just the first dot.
 *
 * The original wrote `term.replace(".", "\\.")`, which escapes one dot and
 * leaves the rest live. Harmless for these terms today and wrong the moment one
 * gains a second dot.
 */
function literal(term: string): string {
  return term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** True when the listing has a file line mentioning this term. */
export function listingMentions(listing: string, term: string): boolean {
  return new RegExp(`^npm notice.*${literal(term)}`, "im").test(listing);
}

/**
 * Every reason this listing must not be published.
 *
 * `where` names which tree was measured, because "as handed" and "after a fresh
 * build" are different facts and a report that blurs them is how this defect
 * survived in the first place.
 */
export function scanPackListing(listing: string, where: string): string[] {
  const problems: string[] = [];
  for (const term of BANNED_FRONTEND) {
    if (listingMentions(listing, term)) {
      problems.push(`${where}: the tarball contains something matching "${term}"`);
    }
  }
  for (const term of BANNED_BUILD_METADATA) {
    if (listingMentions(listing, term)) {
      problems.push(`${where}: the tarball ships "${term}", which is not a deliverable`);
    }
  }
  for (const term of BANNED_SECRETISH) {
    if (listingMentions(listing, term)) {
      problems.push(`${where}: the tarball ships "${term}"`);
    }
  }
  return problems;
}
