// The pure core is exported so it can be tested, reused and audited without
// standing up an agent runtime.
export {
  ADDRESS_CANDIDATE_PATTERN,
  countUnreadableAddressRuns,
  type HiddenAddressScan,
  isValidXrplAddress,
  scanHiddenAddresses,
  validateXrplAddress,
} from "./core/address.ts";
export { BOUNDS, type Bounds } from "./core/bounds.ts";
export { ALLOWED_NODE_HOSTS, assertAllowedNodeUrl, XRPL_NODE_URL } from "./core/node-url.ts";
export { checkRateLimit, pruneWindow } from "./core/ratelimit.ts";
export {
  type AccountReportInput,
  type HiddenAddressNotice,
  renderAccountReport,
  renderCurrencyCode,
  renderOtherAddressesNotice,
  renderRefusal,
  renderRefusalHead,
  sanitizeLedgerText,
} from "./core/render.ts";
export {
  type AccountInfo,
  type AccountLines,
  type TrustLine,
  validateAccountInfoResponse,
  validateAccountLinesResponse,
} from "./core/response.ts";
export {
  type Ok,
  ok,
  type Refusal,
  type RefusalCode,
  type Result,
  refuse,
} from "./core/result.ts";
export {
  type CachedResult,
  type CachedScalar,
  createTurnCache,
  isUuidLike,
  readTurnCache,
  skippedDigest,
  TURN_CACHE_KEY_SEPARATOR,
  type TurnCache,
  type TurnCacheEntry,
  type TurnCacheKeyInput,
  turnCacheKey,
  writeTurnCache,
} from "./core/turncache.ts";
export { default, xrplPlugin } from "./plugin.ts";
export { createXrplProvider, type XrplProviderDeps, xrplAccountProvider } from "./provider.ts";
