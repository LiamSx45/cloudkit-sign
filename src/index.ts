import { createHash, createSign, type KeyLike } from "node:crypto";

export const CLOUDKIT_API_ORIGIN = "https://api.apple-cloudkit.com";

export type CloudKitEnvironment = "development" | "production";
export type CloudKitDatabase = "public" | "private" | "shared";

export type CloudKitBody =
  | string
  | Buffer
  | Uint8Array
  | ArrayBuffer
  | DataView
  | Record<string, unknown>
  | readonly unknown[]
  | null
  | undefined;

export interface SignCloudKitRequestOptions {
  /**
   * The server-to-server key ID from CloudKit Dashboard.
   */
  keyId: string;
  /**
   * The EC private key generated for CloudKit server-to-server access.
   */
  privateKey: KeyLike;
  /**
   * The CloudKit web service URL or subpath. Query parameters must be included.
   */
  url: string | URL;
  /**
   * Request body. Objects and arrays are JSON-stringified with JSON.stringify.
   * Use a string or bytes when exact body bytes matter.
   */
  body?: CloudKitBody;
  /**
   * Date used in the signature and request header. Defaults to the current time.
   */
  date?: Date;
}

export interface SignedCloudKitRequest {
  headers: CloudKitAuthHeaders;
  body: string | Buffer | Uint8Array;
  bodyHash: string;
  date: string;
  signature: string;
  stringToSign: string;
  urlSubpath: string;
}

export interface CloudKitAuthHeaders {
  "X-Apple-CloudKit-Request-KeyID": string;
  "X-Apple-CloudKit-Request-ISO8601Date": string;
  "X-Apple-CloudKit-Request-SignatureV1": string;
}

export interface CloudKitPathOptions {
  container: string;
  environment: CloudKitEnvironment;
  database: CloudKitDatabase;
  operation: string;
  version?: 1;
}

export function signCloudKitRequest(
  options: SignCloudKitRequestOptions,
): SignedCloudKitRequest {
  const keyId = options.keyId.trim();
  if (!keyId) {
    throw new TypeError("CloudKit keyId must be a non-empty string.");
  }

  if (options.privateKey == null || options.privateKey === "") {
    throw new TypeError("CloudKit privateKey is required.");
  }

  const date = toCloudKitISO8601(options.date ?? new Date());
  const body = normalizeBody(options.body);
  const bodyHash = hashBody(body);
  const urlSubpath = toCloudKitUrlSubpath(options.url);
  const stringToSign = `${date}:${bodyHash}:${urlSubpath}`;
  const signature = createSign("sha256")
    .update(stringToSign)
    .sign(options.privateKey, "base64");

  return {
    body,
    bodyHash,
    date,
    headers: {
      "X-Apple-CloudKit-Request-KeyID": keyId,
      "X-Apple-CloudKit-Request-ISO8601Date": date,
      "X-Apple-CloudKit-Request-SignatureV1": signature,
    },
    signature,
    stringToSign,
    urlSubpath,
  };
}

export function cloudKitPath(options: CloudKitPathOptions): string {
  const container = options.container.trim();
  if (!container) {
    throw new TypeError("CloudKit container must be a non-empty string.");
  }

  const operationInput = options.operation.trim();
  if (!operationInput) {
    throw new TypeError("CloudKit operation must be a non-empty string.");
  }

  const operation = operationInput.startsWith("/")
    ? operationInput
    : `/${operationInput}`;

  return `/database/${options.version ?? 1}/${encodeURIComponent(container)}/${options.environment}/${options.database}${operation}`;
}

/**
 * Builds an absolute CloudKit web service URL from a signed subpath.
 */
export function cloudKitUrl(pathOrUrl: string | URL): string {
  if (typeof pathOrUrl !== "string") {
    return pathOrUrl.toString();
  }

  if (/^https?:\/\//i.test(pathOrUrl)) {
    return pathOrUrl;
  }

  const path = pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`;
  return `${CLOUDKIT_API_ORIGIN}${path}`;
}

export function toCloudKitISO8601(date: Date): string {
  if (Number.isNaN(date.getTime())) {
    throw new TypeError("CloudKit signature date must be a valid Date.");
  }

  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function toCloudKitUrlSubpath(url: string | URL): string {
  const parsed = typeof url === "string" ? new URL(url, CLOUDKIT_API_ORIGIN) : url;

  return `${parsed.pathname}${parsed.search}`;
}

export function hashBody(body: string | Buffer | Uint8Array): string {
  return createHash("sha256").update(body).digest("base64");
}

export function normalizeBody(body: CloudKitBody): string | Buffer | Uint8Array {
  if (body == null) {
    return "";
  }

  if (typeof body === "string" || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    return body;
  }

  if (body instanceof ArrayBuffer) {
    return Buffer.from(body);
  }

  if (body instanceof DataView) {
    return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  }

  return JSON.stringify(body);
}
