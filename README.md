# file-server

图床服务 (http://files.ptlgs.org/)

# Development

```
npm i
export ENCRYPTION_PASSWORD=...
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

## Large upload reliability

The browser uploader now sends files through the existing encrypted `/e` upload path in resumable chunks instead of one large request.

What changed:

* Files are sliced into 4MB browser-side chunks.
* Each chunk is encrypted with the existing pre-shared AES-GCM upload tunnel before it leaves the browser.
* The server decrypts and stores each chunk in a temporary upload session.
* Failed chunks are retried automatically with exponential backoff.
* Uploads pause while the browser is offline and continue when the network returns.
* The UI shows percentage, current speed, retry/offline state, and ETA.
* Final storage is unchanged: after all chunks arrive, the server reassembles the original file, calculates the same SHA-256 object key, encrypts it with the existing storage encryption, uploads it to S3, and returns the same `/<sha256>/<filename>` URL format.

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
