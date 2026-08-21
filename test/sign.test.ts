import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { describe, it } from "node:test";

import {
  CLOUDKIT_API_ORIGIN,
  cloudKitPath,
  cloudKitUrl,
  hashBody,
  normalizeBody,
  signCloudKitRequest,
  toCloudKitISO8601,
  toCloudKitUrlSubpath,
} from "../src/index.js";

describe("cloudkit-sign", () => {
  it("formats CloudKit dates without milliseconds", () => {
    assert.equal(
      toCloudKitISO8601(new Date("2026-05-12T16:20:31.123Z")),
      "2026-05-12T16:20:31Z",
    );
  });

  it("rejects invalid dates", () => {
    assert.throws(
      () => toCloudKitISO8601(new Date("not-a-date")),
      /valid Date/,
    );
  });

  it("hashes the exact request body bytes as base64 SHA-256", () => {
    assert.equal(
      hashBody('{"records":[]}'),
      "G4tMC29q0dMlZZUnILwATusfGI9iBF5NVSWuKvjHhDI=",
    );
  });

  it("builds CloudKit database paths", () => {
    assert.equal(
      cloudKitPath({
        container: "iCloud.com.example.app",
        database: "public",
        environment: "development",
        operation: "records/query",
      }),
      "/database/1/iCloud.com.example.app/development/public/records/query",
    );
  });

  it("accepts a leading slash on operations", () => {
    assert.equal(
      cloudKitPath({
        container: "iCloud.com.example.app",
        database: "public",
        environment: "production",
        operation: "/assets/upload",
      }),
      "/database/1/iCloud.com.example.app/production/public/assets/upload",
    );
  });

  it("rejects empty path inputs", () => {
    assert.throws(
      () =>
        cloudKitPath({
          container: " ",
          database: "public",
          environment: "development",
          operation: "records/query",
        }),
      /container/,
    );
    assert.throws(
      () =>
        cloudKitPath({
          container: "iCloud.com.example.app",
          database: "public",
          environment: "development",
          operation: "   ",
        }),
      /operation/,
    );
  });

  it("keeps query parameters in the signed URL subpath", () => {
    assert.equal(
      toCloudKitUrlSubpath(
        "https://api.apple-cloudkit.com/database/1/iCloud.com.example.app/development/public/records/lookup?numbersAsStrings=true",
      ),
      "/database/1/iCloud.com.example.app/development/public/records/lookup?numbersAsStrings=true",
    );
  });

  it("normalizes relative and absolute CloudKit URLs", () => {
    assert.equal(
      cloudKitUrl("/database/1/iCloud.com.example.app/development/public/records/query"),
      `${CLOUDKIT_API_ORIGIN}/database/1/iCloud.com.example.app/development/public/records/query`,
    );
    assert.equal(
      cloudKitUrl("database/1/iCloud.com.example.app/development/public/records/query"),
      `${CLOUDKIT_API_ORIGIN}/database/1/iCloud.com.example.app/development/public/records/query`,
    );
    assert.equal(
      cloudKitUrl(
        "https://api.apple-cloudkit.com/database/1/iCloud.com.example.app/development/public/records/query",
      ),
      "https://api.apple-cloudkit.com/database/1/iCloud.com.example.app/development/public/records/query",
    );
  });

  it("normalizes JSON bodies with JSON.stringify", () => {
    assert.equal(normalizeBody({ records: [] }), '{"records":[]}');
  });

  it("treats nullish bodies as empty strings", () => {
    assert.equal(normalizeBody(undefined), "");
    assert.equal(normalizeBody(null), "");
    assert.equal(hashBody(""), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
  });

  it("normalizes binary body inputs", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    assert.deepEqual(normalizeBody(bytes), bytes);
    assert.deepEqual(
      normalizeBody(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)),
      Buffer.from([1, 2, 3]),
    );
    assert.deepEqual(
      normalizeBody(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)),
      Buffer.from([1, 2, 3]),
    );
  });

  it("rejects missing signing credentials", () => {
    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });

    assert.throws(
      () =>
        signCloudKitRequest({
          keyId: "  ",
          privateKey,
          url: "/database/1/iCloud.com.example.app/development/public/records/query",
        }),
      /keyId/,
    );
    assert.throws(
      () =>
        signCloudKitRequest({
          keyId: "abc123",
          privateKey: "",
          url: "/database/1/iCloud.com.example.app/development/public/records/query",
        }),
      /privateKey/,
    );
  });

  it("returns headers and a verifiable ECDSA signature", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const signed = signCloudKitRequest({
      body: { records: [] },
      date: new Date("2026-05-12T16:20:31.123Z"),
      keyId: "abc123",
      privateKey,
      url: "/database/1/iCloud.com.example.app/development/public/records/query",
    });

    assert.deepEqual(
      {
        keyId: signed.headers["X-Apple-CloudKit-Request-KeyID"],
        date: signed.headers["X-Apple-CloudKit-Request-ISO8601Date"],
        signature: signed.headers["X-Apple-CloudKit-Request-SignatureV1"],
      },
      {
        keyId: "abc123",
        date: "2026-05-12T16:20:31Z",
        signature: signed.signature,
      },
    );
    assert.equal(
      signed.stringToSign,
      "2026-05-12T16:20:31Z:G4tMC29q0dMlZZUnILwATusfGI9iBF5NVSWuKvjHhDI=:/database/1/iCloud.com.example.app/development/public/records/query",
    );

    const verifier = createVerify("sha256");
    verifier.update(signed.stringToSign);
    assert.equal(verifier.verify(publicKey, signed.signature, "base64"), true);
  });

  it("signs empty GET bodies and PEM private keys", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const pem = privateKey.export({ format: "pem", type: "sec1" }).toString();
    const signed = signCloudKitRequest({
      date: new Date("2026-05-12T16:20:31Z"),
      keyId: " abc123 ",
      privateKey: pem,
      url: "/database/1/iCloud.com.example.app/development/public/users/current",
    });

    assert.equal(signed.body, "");
    assert.equal(signed.headers["X-Apple-CloudKit-Request-KeyID"], "abc123");
    assert.equal(
      signed.stringToSign,
      "2026-05-12T16:20:31Z:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:/database/1/iCloud.com.example.app/development/public/users/current",
    );

    const verifier = createVerify("sha256");
    verifier.update(signed.stringToSign);
    assert.equal(verifier.verify(publicKey, signed.signature, "base64"), true);
  });
});
