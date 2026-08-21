# Changelog

## 0.1.1

- Add GitHub Actions CI across Node 18/20/22.
- Add `cloudKitUrl()` helper for absolute CloudKit request URLs.
- Validate empty `keyId`, `privateKey`, container, and operation inputs.
- Document asset upload/rereference operations and public-database S2S access.
- Update `tsx` / `@types/node` and clear the transitive esbuild advisory.
- Fix the test script glob so CI passes on Node 18/20 (shell `**` expansion).

## 0.1.0

- Initial package scaffold.
- Add CloudKit server-to-server request signing helpers.
- Add CloudKit path, date, body normalization, and hashing utilities.
