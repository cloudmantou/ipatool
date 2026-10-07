# Regional App Store HTTP service

This branch extends current upstream ipatool with an independently operated CN / US backend. Authentication uses upstream SAP signing, signed POST redirect handling, bounded transport retries, stable machine identity and phone-number routing.

## Profiles and existing data

Run `--profile cn` or `--profile us` for every regional command. Account keys retain the deployed `account-<sha256(profile)>` names in the encrypted file keyring. Cookies are under `<state>/profiles/<sha256(profile)>/cookies`. The `default` profile retains ordinary upstream CLI behavior. Set `IPATOOL_KEYCHAIN_PASSPHRASE` from a protected credential at runtime; do not put passwords in process arguments or source files.

Each region must use its own OS user, home directory, Apple credentials, artifact directory and signing secret. The service checks Apple storefront 143465 for CN and 143441 for US before preparing, purchasing or downloading. A phone-number routing hint does not replace this check.

## HTTP contract

`GET /api/health` returns `{"success":true}`. It confirms service availability only.

`POST /api/ipa/prepare` and `POST /api/ipa/download` accept `Content-Type: application/json` and:

```json
{"appId":"123456789","appVerId":"987654321"}
```

Identifiers must be positive decimal strings within int64. Duplicate keys, unknown keys, trailing JSON and bodies over 4 KiB are rejected. Each regional process accepts one active preparation / download; concurrent requests receive HTTP 503 with `Retry-After`.

Prepare returns `success` and `data` containing `packageMode: "client-patch-v1"`, `rawDownloadUrl`, optional `expiresAt`, `fileSize`, `appId`, `appVerId`, optional `appName` / `bundleId` / `appVersion`, `purchased`, and `patches`. Each patch has `path`, base64 `content` and lowercase hexadecimal `sha256`. The client downloads the raw IPA and replaces the specified SINF / metadata / artwork ZIP entries. The ticket and patches are account-scoped; keep them out of logs and caches.

Download returns a packaged, SINF-patched IPA through `data.downloadUrl`. URLs under `/api/ipa/artifacts/<id>/app.ipa` contain an expiry and HMAC signature scoped to the region. Artifact responses support byte ranges; expired or modified signatures are rejected. These newly generated URLs use the rebuilt signing format; they do not promise compatibility with outstanding links from a lost-source implementation.

Errors use `{"success":false,"error":{"code":"...","message":"..."}}`. Upstream response bodies and credentials are not included in HTTP errors or service logs. `auth_code_required` means an administrator must complete 2FA. Transient refresh failures back off from 30 seconds up to 10 minutes; successful refresh clears the failure state. A missing license can trigger acquisition only after a catalog lookup confirms the app is free.

## Start a region

```sh
ipatool --profile cn --non-interactive serve \
  --listen 127.0.0.1:18082 \
  --public-base-url https://cn.example.com \
  --artifact-dir /var/lib/ipatool-cn/artifacts \
  --artifact-signing-key-file /run/credentials/ipatool-cn.service/artifact-signing-key \
  --apple-email-credential-file /run/credentials/ipatool-cn.service/apple-email \
  --apple-password-credential-file /run/credentials/ipatool-cn.service/apple-password
```

The service requires a loopback listen address and a public HTTPS origin. Credential files must be private regular files. A group-read bit is accepted only for files supplied inside the private systemd `CREDENTIALS_DIRECTORY` (Ubuntu exposes these as 0440). Preserve all password spaces and punctuation; only a final file line ending is removed.

Use systemd LoadCredential and a launch wrapper to export the keyring passphrase. Set `HOME` and `XDG_CACHE_HOME` to the region's writable data directories. Keep resource caches out of temporary directories. Build natively with CGO enabled; the keyring dependency requires CGO.

## Deployment and validation

Back up each region's encrypted account files, cookies, systemd configuration and previous executable before deployment. Store backups with root-only permissions. Keep source and binaries in durable, versioned directories rather than `/tmp`.

SAP dynamically loads a hash-verified Unicorn library and Apple framework assets. First startup needs outbound access to the upstream artifact URLs. Test under the intended OS user and service restrictions. `MemoryDenyWriteExecute=yes` can prevent Unicorn's generated code; verify this independently before changing the two service units. Keep other sandbox restrictions in place.

Validate the candidate with a copied account state and a separate listen port. Check real authentication, returned storefront, restart persistence, refresh, prepare patch contents, signed artifact download and byte ranges. Then deploy one region at a time, retaining the old executable and state for rollback. Do not treat health checks, compilation or mock tests as real-account acceptance.

To complete initial login or 2FA without exposing the Apple password in arguments:

```sh
ipatool --profile cn --non-interactive auth login \
  --apple-email-credential-file /protected/apple-email \
  --apple-password-credential-file /protected/apple-password
```

If needed, repeat once with `--auth-code` and the current six-digit code. Non-interactive login returns a failure exit code when verification is still required. Keep administrative login output private, and perform account state changes with the regional service stopped or against an isolated copy.

## Local checks

```sh
go generate ./...
go test ./...
go test -race ./pkg/server ./pkg/profile ./pkg/appstore ./cmd
go vet ./pkg/server ./pkg/profile ./pkg/appstore ./cmd
go build .
```

The SAP integration test requires internet access and populates a validated resource cache. These checks can also run in an operator-managed Linux CI job without production credentials. The branch does not install a new workflow or deploy automatically.
