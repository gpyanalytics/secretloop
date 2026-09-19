/**
 * THE ANCESTOR CHAIN ABOVE THE CONSENT STORE (POSIX only).
 *
 * The store's own two directories have been checked since PR #90, each record since PR #92, and
 * macOS extended ACLs since PR #93. None of that looks at the path ABOVE the store, and measuring
 * what that costs gave two different answers per platform:
 *
 *   Linux   — an account that can write the store's parent renamed the whole store away and put
 *             its own in place. Against that substituted store the product refused on ownership
 *             and transmitted nothing, so in the cases measured the effect was denial of service
 *             rather than disclosure or an accepted approval. That is a statement about the cases
 *             measured, not a general theorem.
 *   macOS   — worse, and the reason this exists. An inheritance ACE on the parent is inherited by
 *             a store and a record the OWNER'S OWN PROCESS creates, and the creation mode does not
 *             neutralise it there. The adversary never has to own anything.
 *
 * THE RULE. Every component of the path is a real directory owned by the effective uid or by a
 * trusted platform principal, and is not writable by anyone else. Symbolic links are followed but
 * both the literal and the resolved chains are checked, so a link cannot be repointed by someone
 * who is not already trusted. The walk goes to the filesystem root: a mount boundary is not a
 * security boundary, because whoever can write the directory a filesystem is mounted on can
 * arrange what is seen there.
 *
 * WHAT IT IS NOT. A chain of `lstat` calls at different instants is not an atomic snapshot of the
 * filesystem. It describes the chain now: a component re-permissioned afterwards is not seen, it
 * is not atomic with the store checks that follow it or with any later open, and it revokes no
 * descriptor another process already holds.
 */

import { lstatSync, realpathSync } from "fs";
import * as path from "path";

/**
 *   unsafe-parent-posix  a directory on the path to the store can be modified by another account
 *   parent-unreadable    a directory on that path could not be inspected at all
 */
export type ParentChainProblem = "unsafe-parent-posix" | "parent-unreadable";

export type ParentChainVerdict<P = ParentChainProblem> = { ok: true } | { ok: false; problem: P };

/**
 * Owners that may hold a directory above the store without the adversary model being violated.
 * uid 0 owns the upper filesystem on both platforms; on macOS the system volume roots are also
 * root-owned, so no separate case is needed for them. Anything else must be the effective uid.
 */
function trustedOwner(uid: number, euid: number): boolean {
  return uid === euid || uid === 0;
}

/**
 * Whether a component can be modified by somebody who is neither the effective uid nor root.
 *
 * Group write is treated as unsafe wherever it appears, which is the conservative reading and the
 * one P-1 approved. A group MIGHT contain only the owner — a per-user group, as most Linux
 * distributions create — in which case the grant is harmless. There is no portable way to
 * establish that: `process.getgroups()` reports this process's groups, not the membership of an
 * arbitrary group, and with NIS, LDAP or Directory Services the membership is not on local disk
 * at all. Rather than guess, every group-write bit is refused and the cost is documented.
 *
 * THE STICKY EXCEPTION, and exactly how far it reaches. `/tmp` is mode 1777 and a great deal of
 * software, including this project's own test fixtures, lives under it. Measured as a second
 * ordinary account in a sticky, root-owned, world-writable directory:
 *
 *   - deleting the owner's store: DENIED. Renaming it: DENIED. Reading its record: DENIED.
 *     That is what sticky is for, and it holds.
 *   - creating a name that does NOT yet exist: ALLOWED. Sticky restricts rename and delete, not
 *     create, so the store can be PRE-PLANTED before the owner ever runs.
 *   - if the sticky directory is owned by the ADVERSARY instead of root: deleting the owner's
 *     store is ALLOWED. A directory's owner may always remove its entries, sticky or not.
 *
 * So sticky is accepted only when the directory is also owned by a trusted principal, and even
 * then it does not make pre-planting impossible. What makes pre-planting tolerable is a separate,
 * already-shipped check: a pre-planted store is owned by the adversary, and the ownership rule
 * refuses it — measured, `foreign-owner` from both `listRecords` and `writeRecord`. The residual
 * is therefore a denial of service that this rule does not close, and saying so is the point.
 */
function otherWritable(mode: number, uid: number, euid: number): boolean {
  const groupWrite = (mode & 0o020) !== 0;
  const otherWrite = (mode & 0o002) !== 0;
  const sticky = (mode & 0o1000) !== 0;
  if (!groupWrite && !otherWrite) return false;
  // Sticky only earns the exception in a directory a trusted principal owns.
  if (sticky && trustedOwner(uid, euid)) return false;
  return true;
}

/** Every ancestor of `p`, itself first, up to the filesystem root. */
function chainOf(p: string): string[] {
  const out: string[] = [];
  let cur = path.resolve(p);
  for (;;) {
    out.push(cur);
    const up = path.dirname(cur);
    if (up === cur) break;
    cur = up;
  }
  return out;
}

/**
 * The directories to inspect for `dir`: its own literal chain, and — when any part of it is a
 * symbolic link — the resolved chain as well.
 *
 * Both are needed. Checking only the resolved chain would miss the directory that HOLDS a link,
 * and whoever can write that directory can repoint the link. Checking only the literal chain
 * would miss where the link actually leads. On macOS this is not hypothetical: `/var` and `/tmp`
 * are links into `/private`, so the two chains genuinely differ on every temp path.
 */
export function chainTargets(dir: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const add = (p: string): void => {
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  };
  for (const c of chainOf(dir)) add(c);
  let resolved: string | null = null;
  try {
    resolved = realpathSync(dir);
  } catch {
    // The store itself may not exist yet; resolve the deepest ancestor that does.
    for (const c of chainOf(dir).slice(1)) {
      try {
        resolved = realpathSync(c);
        break;
      } catch {
        /* keep walking up */
      }
    }
  }
  if (resolved) for (const c of chainOf(resolved)) add(c);
  return out;
}

/**
 * A ceiling on how many directories ONE WALK will inspect.
 *
 * Measured boundary: the predicate is `> 64`, so 64 components are accepted and 65 refuse. It
 * counts COMPONENTS, deduplicated across the literal and resolved chains — a component common to
 * both is visited once — which is not the same as path depth. Measured: a chain with no symbolic
 * link on it has one component per level, so 64 components is 64 levels; a chain with a link has
 * both spellings, so the same 64 components is about 32 levels. Two macOS paths were measured and
 * they differ: the real home `/Users/<user>` had no link and 3 components, while a temp path under
 * `/var/folders` had one (`/var` into `/private/var`) and 12. Not every macOS path contains a
 * symbolic link; these two did and did not respectively.
 *
 * This is NOT the only limit that applies on macOS. `MAX_ANCESTOR_INSPECTIONS` in consent.ts caps
 * inspections per call at 40, and the two are ORDERED: this length check runs before the loop, so
 * a path of 65+ components refuses here and the per-component cap is never reached, while a path
 * of 41..64 components passes here and trips the inspection cap instead. On macOS the effective
 * ceiling is therefore 40 components, not 64.
 */
export const MAX_CHAIN_COMPONENTS = 64;

/**
 * An extra per-component test, used on macOS to add the extended-ACL rule. Its problem code is
 * its own: an ancestor carrying an ACE and an ancestor that could not be inspected are different
 * answers, and flattening both into "unsafe parent" would tell a user with a broken tool that
 * their filesystem is at fault.
 */
export type ComponentHook<P> = (dir: string) => ParentChainVerdict<P>;

export function checkParentChain<P = never>(
  dir: string,
  euid: number,
  hook?: ComponentHook<P>
): ParentChainVerdict<ParentChainProblem | P> {
  // The STORE ITSELF is not part of this walk. It has its own rules -- ownership, mode, links,
  // and on macOS its own extended-ACL rule -- each with a reason that says more than "a directory
  // on the path is unsafe". This check is about everything ABOVE it.
  //
  // BOTH spellings of the store have to be excluded, not just the literal one. `chainTargets`
  // returns the resolved chain as well, and on macOS the two differ on every temp path because
  // `/var` is a link into `/private`. Filtering only `path.resolve(dir)` left the store's resolved
  // twin in the walk, so an ACE on the store came back as an unsafe ANCESTOR -- the wrong object
  // and the wrong guidance. A test caught it.
  const literal = path.resolve(dir);
  let resolvedStore: string | null = null;
  try {
    resolvedStore = realpathSync(dir);
  } catch {
    /* not there yet; the literal form is the only spelling that exists */
  }
  const targets = chainTargets(dir).filter((c) => c !== literal && c !== resolvedStore);
  if (targets.length > MAX_CHAIN_COMPONENTS) return { ok: false, problem: "parent-unreadable" };
  for (const component of targets) {
    let st;
    try {
      st = lstatSync(component);
    } catch {
      return { ok: false, problem: "parent-unreadable" };
    }
    if (st.isSymbolicLink()) {
      // A link is not refused outright — `/var` is one on macOS, and refusing it would refuse
      // every macOS temp path. The directory holding it and the place it leads are both in
      // `targets` and both checked.
      //
      // But the LINK'S OWN OWNER still has to be trusted, and an earlier version of this skipped
      // straight past that. Whoever owns a symbolic link can delete it and point it somewhere
      // else at any moment, so an untrusted owner here is continuous control of the path rather
      // than a snapshot risk. Measured: in a sticky, root-owned, world-writable directory a
      // second ordinary account planted a link, this walk returned ok, and the same account then
      // removed it and repointed it. Sticky restricts rename and delete, not create, so the
      // sticky exception is the only thing that lets an untrusted link onto an accepted path —
      // which is exactly why the two rules have to be read together.
      //
      // A link's mode is meaningless on both platforms (always 0777), so only ownership is
      // tested here; what the link leads to is judged on its own terms as a separate component.
      if (!trustedOwner(st.uid, euid)) return { ok: false, problem: "unsafe-parent-posix" };
      continue;
    }
    if (!st.isDirectory()) return { ok: false, problem: "unsafe-parent-posix" };
    if (!trustedOwner(st.uid, euid)) return { ok: false, problem: "unsafe-parent-posix" };
    if (otherWritable(st.mode, st.uid, euid)) return { ok: false, problem: "unsafe-parent-posix" };
    if (hook) {
      const extra = hook(component);
      if (!extra.ok) return extra;
    }
  }
  return { ok: true };
}
