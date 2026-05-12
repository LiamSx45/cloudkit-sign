# cloudkit-sign

[![npm version](https://img.shields.io/npm/v/cloudkit-sign.svg)](https://www.npmjs.com/package/cloudkit-sign) [![license](https://img.shields.io/npm/l/cloudkit-sign.svg)](./LICENSE) [![types](https://img.shields.io/npm/types/cloudkit-sign.svg)](https://www.npmjs.com/package/cloudkit-sign)

Minimal, well-typed CloudKit server-to-server request signing for Node.js.

Apple's CloudKit Web Services docs describe the signing flow, but the details are easy to get subtly wrong: hash the body first, remove milliseconds from the date, sign the URL subpath instead of the full origin, and include query parameters. This package keeps that small ritual in one tested place.

## Install

```sh
npm install cloudkit-sign
```

## Usage

```ts
import { readFileSync } from "node:fs";
import { cloudKitPath, signCloudKitRequest } from "cloudkit-sign";

const privateKey = readFileSync("./eckey.pem", "utf8");
const path = cloudKitPath({
  container: "iCloud.com.example.app",
  environment: "development",
  database: "public",
  operation: "records/query",
});

const body = {
  query: {
    recordType: "Note",
  },
};

const signed = signCloudKitRequest({
  keyId: process.env.CLOUDKIT_KEY_ID!,
  privateKey,
  url: path,
  body,
});

const response = await fetch(`https://api.apple-cloudkit.com${path}`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    ...signed.headers,
  },
  body: signed.body,
});

if (!response.ok) {
  throw new Error(await response.text());
}
```

## API

### `signCloudKitRequest(options)`

Returns the CloudKit authentication headers plus helpful debug fields.

```ts
const signed = signCloudKitRequest({
  keyId: "your-cloudkit-key-id",
  privateKey: "-----BEGIN EC PRIVATE KEY-----\n...",
  url: "/database/1/iCloud.com.example.app/development/public/users/current",
  body: "",
});
```

The returned `headers` object contains:

```ts
{
  "X-Apple-CloudKit-Request-KeyID": string;
  "X-Apple-CloudKit-Request-ISO8601Date": string;
  "X-Apple-CloudKit-Request-SignatureV1": string;
}
```

### `cloudKitPath(options)`

Builds a CloudKit database URL subpath:

```ts
cloudKitPath({
  container: "iCloud.com.example.app",
  environment: "production",
  database: "public",
  operation: "records/lookup",
});
```

## Important Details

- Generate the EC key with `openssl ecparam -name prime256v1 -genkey -noout -out eckey.pem`.
- Upload the public key to CloudKit Dashboard and use the generated Key ID.
- The signed date is valid for 10 minutes, so your server clock needs to be accurate.
- For `GET` requests, pass no body or an empty string.
- For JSON bodies, this package signs the exact `JSON.stringify` output it returns as `signed.body`. If you need a custom serializer, pass your already-serialized string or bytes.
- Sign the CloudKit URL subpath, not `https://api.apple-cloudkit.com`.
- Query parameters are part of the signature and must be included.

## Common Operations

`cloudkit-sign` does not wrap CloudKit itself. It signs any CloudKit Web Services request, so you can use it with the operations Apple exposes today and any new ones they add later.

Pass one of these values as `operation` to `cloudKitPath()`:

```ts
// Records
"records/lookup";
"records/query";
"records/modify";
"records/changes";
"records/resolve";

// Zones
"zones/list";
"zones/lookup";
"zones/modify";
"zones/changes";

// Subscriptions
"subscriptions/list";
"subscriptions/lookup";
"subscriptions/modify";

// Users
"users/current";
"users/lookup";
"users/lookup/email";
"users/lookup/phone";
```

You can also pass a leading slash if you prefer:

```ts
cloudKitPath({
  container: "iCloud.com.example.app",
  environment: "production",
  database: "public",
  operation: "/records/modify",
});
```

## References

- [Apple CloudKit Web Services: Composing Web Service Requests](https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/CloudKitWebServicesReference/SettingUpWebServices.html)

## License

MIT
