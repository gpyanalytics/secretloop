/**
 * API-description-document classifier for the generic entropy tier.
 *
 * Contract frozen in entropy-scope-v1-preimplementation-freeze-v0.4.0.md
 * (benchmark workspace, Phase A.1 amendment §A.1.1-A.1.3). This decides ONE
 * thing: whether a scanned text is an OpenAPI / Swagger / AsyncAPI description,
 * in which case the generic-high-entropy pass is not run over it
 * (whole-document; see scanner.ts). Named rules never consult it.
 *
 * Pure and deterministic: no I/O, no logging, nothing retained from the parse.
 * Returns only a boolean -- never the parsed document.
 *
 * The model is CONTENT + EXTENSION. The extension is mandatory and decides
 * which content test runs; an extensionless file never qualifies, whatever it
 * contains. The path is the LOGICAL path -- an archive member's own path, not
 * its container's -- and only its basename's extension is read. Directory
 * names never decide anything.
 */

/** Code units of a YAML text the marker must fall within. */
export const API_DOCUMENT_YAML_HEAD = 65536;

/**
 * Top-level YAML declaration: the key at column 0, lower-case, followed by an
 * optionally quoted value whose first character is a digit. Multiline, so
 * comments, `---`, directives and other keys may precede it; an indented (i.e.
 * nested) key does not match. A BOM is not stripped, so a marker on line 1 of a
 * BOM-prefixed file does not match -- part of the frozen contract.
 */
const YAML_MARKER = /^(openapi|swagger|asyncapi):\s*['"]?\d/m;

function extensionOf(logicalPath: string): string {
  const base = logicalPath.slice(logicalPath.lastIndexOf("/") + 1);
  const dot = base.lastIndexOf(".");
  // A leading dot alone (`.json`) names a dotfile, not an extension.
  if (dot <= 0) return "";
  return base.slice(dot).toLowerCase();
}

function hasOwn(doc: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(doc, key);
}

function isJsonApiDocument(text: string): boolean {
  let doc: unknown;
  try {
    // Whole text, normal JSON.parse: no BOM stripping, no repair, no JSON5. A
    // parse failure is simply "not an API document" and entropy runs as before.
    doc = JSON.parse(text);
  } catch {
    return false;
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return false;
  const d = doc as Record<string, unknown>;
  // Case-sensitive, top-level own properties only. No version-format check on
  // the marker string; a number is not a string and does not qualify. Nested
  // occurrences and prose mentions never count. Duplicate keys resolve as
  // JSON.parse resolves them.
  if (
    (typeof d.openapi === "string" || typeof d.swagger === "string") &&
    (hasOwn(d, "paths") || hasOwn(d, "components") || hasOwn(d, "definitions"))
  ) {
    return true;
  }
  return typeof d.asyncapi === "string" && hasOwn(d, "channels");
}

function isYamlApiDocument(text: string): boolean {
  return YAML_MARKER.test(text.slice(0, API_DOCUMENT_YAML_HEAD));
}

/**
 * True when `text`, scanned under `logicalPath`, is an API description
 * document. Never throws.
 */
export function isApiDocument(logicalPath: string, text: string): boolean {
  switch (extensionOf(logicalPath)) {
    case ".json":
      return isJsonApiDocument(text);
    case ".yaml":
    case ".yml":
      return isYamlApiDocument(text);
    default:
      return false;
  }
}
