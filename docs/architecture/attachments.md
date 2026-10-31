# File attachments and the "Document" item type

> **Draft.** Not reviewed by cryptographers and not audited. The blob format may still change before the first release that ships it.

This document describes wave G2 as implemented: files attached to any item, and the `document` item category (a file with notes). The planning sketch is in docs/planning/feature-gap.md §5.9 (German); where this document differs, this document is what the code does.

## What the server learns

| The server **cannot** | because |
| --- | --- |
| read a file, its name or its type | the file is encrypted on the device with its own key; name, type, size and key are stored in the encrypted item |
| hand out one file in place of another | every chunk is bound to the attachment's ID (and the key is per file) |
| reorder, drop, duplicate or cut off chunks | the chunk index and a "last chunk" flag are authenticated |
| keep a file readable for someone who lost access to the vault | — it **can**: see below |

What it **can** see or do: the number and the encrypted size of an item's attachments (padding is not added), when they were uploaded and by whom, and which items have attachments. It can withhold or delete blobs. A removed member who downloaded a file (or its key, which is in the item) may keep it; vault key rotation re-encrypts items but **does not** re-encrypt attachment blobs, so a former member who kept an old copy of the item still has the file key. Change or remove sensitive files after removing someone.

## Encryption (`passbox_core::file_crypto`)

Each attachment has a random 256-bit `file_key`. The blob follows the STREAM construction with XChaCha20-Poly1305:

```
blob   = header (24 B) || chunk_0 || ... || chunk_n
header = "PBXF" || version 0x01 || chunk_size (u32 BE, 1 MiB) || nonce_prefix (15 random bytes)
nonce  = nonce_prefix || index (u64 BE) || last (0x00 / 0x01)
aad    = "passbox/v1/file|{file_id}|{index}|{last}" || 0x00 || header
chunk  = XChaCha20-Poly1305(file_key, nonce, plaintext_i, aad)        (plaintext + 16-byte tag)
```

Every chunk but the last holds exactly `chunk_size` bytes; the last holds at most `chunk_size` (an empty file is one empty last chunk). Decryption fails on a wrong key or file ID, a modified header or chunk, reordered or swapped chunks, a blob cut off at a chunk boundary and trailing bytes (`file_crypto::tests`). Readers accept chunk sizes from 1 KiB to 16 MiB, so the size can change in later versions.

The item ID is deliberately not bound: moving an item between vaults (B5) keeps its attachments without re-encrypting them. The file key is protected by the item, and the item by the vault key.

Clients encrypt and decrypt in chunks (`FileEncryptor`/`FileDecryptor` in Rust and WebAssembly). The web app and the Rust client currently hold the whole file in memory while uploading or downloading (up to the server's size limit, 100 MiB by default); the format allows true streaming later without a change.

## Item data

```json
"attachments": [
  { "id": "<26-char ID>", "name": "passport.pdf", "type": "application/pdf",
    "size": 482113, "key": "<Base64url file key>", "createdAt": 1761300000000 }
]
```

`attachments` is an item key like `passkeys`; clients that do not know it keep it unchanged. `PassboxClient.updateItem` (TypeScript) and `Client::update_item` (Rust) always keep the stored list, so an editor with an older copy can neither drop nor resurrect attachments; they change only through the calls below.

## Server

Blobs are stored outside the database by a `BlobStore` (`crates/server/src/blobs.rs`). This version ships the disk store: `{PASSBOX_BLOB_DIR}/{first two characters of the ID}/{ID}`, written to `tmp/` first and renamed when complete. The database keeps `attachments(id, item_id, vault_id, uploaded_by, owner_type, owner_id, size, created_at)` (migration [`0001_baseline.sql`](https://github.com/passboxnet/passbox-server/blob/main/migrations/0001_baseline.sql), with row level security like every tenant table).

**S3:** no S3-compatible backend is included yet. The available Rust S3 clients are large (the AWS SDK) or not audited, which does not fit the dependency policy; `BlobStore` is the seam for adding one. Today, put `PASSBOX_BLOB_DIR` on a volume (or an S3 FUSE mount if you need object storage) and back it up together with the database.

| Endpoint | Who | What |
| --- | --- | --- |
| `PUT /api/v1/attachments/{id}?itemId=…` | writers of the item's vault | Stores the encrypted blob (raw body). IDs come from the client; a blob cannot be replaced (409). At most 50 per item. 403 `file_too_large` / `quota_exceeded`. |
| `GET /api/v1/attachments/{id}` | readers of the item's vault | The blob (`application/octet-stream`, `Cache-Control: no-store`). |
| `DELETE /api/v1/attachments/{id}` | writers | Deletes row and blob. |
| `GET /api/v1/attachments/usage` | signed in | `{ maxFileSize, usage: [{ owner: "account" \| orgId, used, quota }] }` |

Deleting an item permanently deletes its attachments. Blobs whose row is gone (vault or organization deleted, interrupted uploads) are swept hourly once they are an hour old. Moving an item moves its attachments to the target vault and counts them against the target's quota.

**Limits and quotas** (MiB; 0 = unlimited):

| Variable | Default | Meaning |
| --- | --- | --- |
| `PASSBOX_BLOB_DIR` | `blobs` (Docker: `/data/blobs`) | Where blobs live |
| `PASSBOX_ATTACHMENT_MAX_MB` | 100 | Largest file |
| `PASSBOX_ATTACHMENT_QUOTA_MB` | 0 | Storage per account for its personal vaults |
| `PASSBOX_ORG_ATTACHMENT_QUOTA_MB` | 0 | Storage per organization for its shared vaults |

Self-hosted servers are unlimited by default. The hosted service sets the quotas per plan through these settings until plans exist in the server (H5).

## Clients

| | Add | Read | Remove |
| --- | --- | --- | --- |
| Rust | `client.add_attachment(item_id, name, media_type, &bytes)` | `client.attachment_data(item_id, attachment_id)` | `client.remove_attachment(item_id, attachment_id)` |
| FFI | `addAttachment(itemId, name, mediaType, data)` | `attachmentData(itemId, attachmentId)`; `Item.attachments` lists them | `removeAttachment(itemId, attachmentId)` |
| TypeScript | `client.addAttachment(itemId, { name, type, data })` | `client.attachmentData(itemId, attachmentId)` | `client.removeAttachment(itemId, attachmentId)` |

The web app shows attachments in the item details: add by picking or dropping files, download, remove (confirmed), and a preview for images and PDFs. The preview is a `blob:` URL in a sandboxed `<iframe>` (`sandbox=""` for images; `sandbox="allow-scripts"` for PDFs, which the browser's viewer needs, still in an opaque origin); the CSP allows `frame-src blob:` and `img-src blob:` for this. Browsers that do not render PDFs in sandboxed frames show an empty frame; the dialog says to download the file then. The iOS and Android apps list attachments in the item details, open them through a private temporary file (deleted afterwards) and add files from the system picker.
