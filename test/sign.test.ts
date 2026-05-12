import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { describe, it } from "node:test";

import {
  cloudKitPath,
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

  it("keeps query parameters in the signed URL subpath", () => {
    assert.equal(
      toCloudKitUrlSubpath(
        "https://api.apple-cloudkit.com/database/1/iCloud.com.example.app/development/public/records/lookup?numbersAsStrings=true",
      ),
      "/database/1/iCloud.com.example.app/development/public/records/lookup?numbersAsStrings=true",
    );
  });

  it("normalizes JSON bodies with JSON.stringify", () => {
    assert.equal(normalizeBody({ records: [] }), '{"records":[]}');
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
});
