# file-server

图床服务 (http://files.ptlgs.org/)

# Development

```
npm i
export ENCRYPTION_PASSWORD=...
export PROXY=https://... # optional, used mostly on dev manchine, not used in production
export S3_ACCESS_KEY=...
export S3_BUCKET=...
export S3_ENDPOINT=...
export S3_REGION=...
export S3_SECRET_KEY=...
node index.js
```

然后访问 http://localhost:3000/

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
