# traiga_be

## Stream publish credentials

Set `STREAM_KEY_ENCRYPTION_KEY` to a stable random value of at least 32 characters in the backend environment. The backend uses AES-GCM to encrypt publish credentials at rest and a keyed HMAC digest to verify publishing requests. Keep this value backed up and unchanged between deployments; changing it requires re-encrypting the stored credentials. If it is omitted, the backend derives the key from `JWT_SECRET` for compatibility.

The public room name remains a room identifier. The publish credential is a separate random secret and is sent only to the authenticated stream owner; SRS receives it as the `publish_secret` query parameter and the backend verifies its HMAC digest.
