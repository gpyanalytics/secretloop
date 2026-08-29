/**
 * Verification over a whole workspace scan.
 *
 * Split out of workspace.ts so that importing the scanner does not import the
 * verifiers. workspace.ts is the one seam the CLI, the editor and the MCP
 * server all share, and while `verifyFindings` lived in it every consumer of
 * `scanFiles` also linked eighteen provider transports and the AWS SDK --
 * including the MCP server, which has no verification tool at all. Code that
 * can transmit a credential should be reachable only from a caller that meant
 * to transmit one, and that is an import-graph property, not a policy one.
 *
 * The scanning half stayed put: invariant 3 of the MCP layer is that there is
 * exactly one path into the scanner, so what moved is the outbound half.
 */
import { Finding } from "./scanner";
import { VerificationCache, VerifyContext, verifyFindings } from "./verify";
import { ScannedFile } from "./workspace";

export interface VerifyScanOptions {
  cache?: VerificationCache;
  concurrency?: number;
  /** Test hook: the context each finding was verified with. */
  onContext?: (finding: Finding, context: VerifyContext) => void;
}

/**
 * Verifies a whole scan in one bounded pass, and reports what actually left.
 *
 * One pass rather than one per file: a workspace scan is the widest fan-out
 * this tool has, and the returned list is the record of how many credentials
 * were transmitted across the entire scan. A per-file count would understate it
 * in the one place accuracy matters most.
 *
 * Context is resolved per finding, since the AWS verifier reads the text of the
 * file its access key came from to find the secret key beside it.
 */
export async function verifyScannedFiles(
  scanned: ScannedFile[],
  fetchImpl: typeof fetch,
  options: VerifyScanOptions = {}
): Promise<Finding[]> {
  const findings = scanned.flatMap((s) => s.findings);
  const texts = new Map(scanned.map((s) => [s.path, s.text]));
  const sent: Finding[] = [];

  await verifyFindings(
    findings,
    (finding) => {
      const context: VerifyContext = {
        fullText: texts.get(finding.file ?? "") ?? "",
        fetchImpl,
      };
      options.onContext?.(finding, context);
      return context;
    },
    {
      cache: options.cache,
      concurrency: options.concurrency,
      onOutbound: (f) => sent.push(f),
    }
  );

  return sent;
}
