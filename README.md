# file-server

图床服务 (http://files.ptlgs.org/)

# Development

```
npm i
export ENCRYPTION_PASSWORD=...
export JWT_SECRET=...
export FRONTEND_PASSWORD=... # existing single login password
# or: export FRONTEND_PASSWORDS='password-a,password-b'
export PROXY=https://... # optional, used for outbound HTTP and S3 if S3_PROXY is unset
export S3_PROXY=https://... # optional, overrides PROXY for S3 uploads/downloads
export S3_ACCESS_KEY=...
export S3_BUCKET=...
export S3_ENDPOINT=...
export S3_REGION=...
export S3_SECRET_KEY=...
node index.js
```

然后访问 http://localhost:3000/

`FRONTEND_PASSWORD`/`FRONTEND_PASSWORDS` is checked by `frontendServer.js` when logging in. The upload backend does not check this password directly; it verifies the JWT upload token signed with `JWT_SECRET`.

To allow multiple login passwords, set `FRONTEND_PASSWORDS` to a comma-separated list or JSON array. All configured passwords have the same access. To revoke one, remove it from `FRONTEND_PASSWORDS` and restart the frontend server.

## Large upload reliability

The browser uploader now sends files through the existing encrypted `/e` upload path in resumable chunks instead of one large request.

What changed:

* Files are sliced into 4MB browser-side chunks.
* Each chunk is encrypted with the existing pre-shared AES-GCM upload tunnel before it leaves the browser.
* The server decrypts and stores each chunk in a temporary upload session.
* Failed chunks are retried automatically with exponential backoff.
* Uploads pause while the browser is offline and continue when the network returns.
* The UI shows percentage, current speed, retry/offline state, and ETA.
* Final storage still uses the existing encryption flow: after all chunks arrive, the server reassembles the original file, calculates the SHA-256 digest, encrypts it, uploads it to S3 using a deterministic 14-character Crockford Base32 key derived from that digest, and returns the `/<14-char-crockford-base32-key>/<filename>` URL format.
* New short URLs are case-insensitive on download. For 14-character keys, `O` normalizes to `0`, and `I`/`L` normalize to `1`.
* Existing long SHA-256 URLs continue to work as long as their original S3 objects remain present.

Optional environment variables:

```bash
export MAX_UPLOAD_BYTES=$((500 * 1024 * 1024))       # default: 500MB
export MAX_UPLOAD_CHUNK_BYTES=$((8 * 1024 * 1024))   # server-side max accepted chunk size
export UPLOAD_TMP_DIR=/tmp/file-server-chunk-uploads # where temporary chunks are stored
export CHUNK_UPLOAD_TTL_MS=$((24 * 60 * 60 * 1000))  # temporary upload cleanup age
export CACHE_DIR=diskcache                            # mount a K8S PVC here for persistent cache
export CACHE_MAX_USAGE_RATIO=0.9                      # default cache cap when CACHE_MAX_BYTES is unset
export CACHE_MAX_BYTES=10Gi                           # optional explicit cache cap
export CACHE_MIN_FREE_BYTES=1Gi                       # optional filesystem free-space reserve
```

On startup the server logs the detected cache filesystem size. Some Kubernetes storage backends report the backing host/NFS filesystem size instead of the PVC request; set `CACHE_MAX_BYTES` when the detected size is not the usable cache budget.

The legacy `/e` and `/upload` endpoints are still present for compatibility, but the UI uses the chunked encrypted upload flow.

# ES

```
PUT /file-server-logs
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1
  },
  "mappings": {
    "properties": {
      "timestamp": {
        "type": "date"
      },
      "user_id": {
        "type": "keyword"
      },
      "file_name": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "file_url": {
        "type": "keyword"
      },
      "file_size": {
        "type": "long"
      }
    }
  }
}
```

# TODO

https://ptlgs.youtrack.cloud/issue/PTL-11

* 防盗链
* 自动图片压缩功能
