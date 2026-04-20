# Content JSON Schema

## 1. 设计目标

本文件用于单独固定以下三类内容文件的 JSON 结构：

- `content.draft.json`
- `content.latest.json`
- `content.<version>.json`

约束目标：

- `draft` 只保存 `Node.id` 引用与顺序
- `latest` / `version` 保存完整节点快照
- 快照中的节点坐标以 `uuid + version` 为准
- 结构稳定，可作为 API、存储和导出层的共同约束

## 2. 通用约束

所有内容文件都建议满足：

- 顶层必须是对象
- 顶层必须包含 `contentId`
- 顶层必须包含 `state`
- 顶层必须包含 `nodes`
- `nodes` 必须为数组

建议约定：

- `contentId` 使用字符串
- `state` 只能取 `draft` / `latest` / `version`
- `label` 为可选字符串
- `version` 在 `draft` 中省略或为 `null`，在 `latest` 和 `version` 中必须为纯整数
- 快照文件名中的 `<version>` 使用 6 位零填充数字
- `label` 是展示字段，不参与版本定位

## 3. Draft Schema

### 3.1 语义

`content.draft.json` 表示当前草稿编排，只保存节点引用与顺序，不保存节点完整内容。

### 3.2 结构

```json
{
  "contentId": "content_xxx",
  "state": "draft",
  "label": "draft",
  "nodes": [
    { "nodeId": 101 },
    { "nodeId": 205 }
  ]
}
```

### 3.3 字段约束

- `contentId`: string, required
- `state`: string, required, must equal `draft`
- `label`: string, optional
- `nodes`: array, required

每个 `nodes[]` 元素：

- `nodeId`: integer, required

### 3.4 JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "content.draft.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["contentId", "state", "nodes"],
  "properties": {
    "contentId": {
      "type": "string",
      "minLength": 1
    },
    "state": {
      "const": "draft"
    },
    "label": {
      "type": "string"
    },
    "nodes": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["nodeId"],
        "properties": {
          "nodeId": {
            "type": "integer",
            "minimum": 1
          }
        }
      }
    }
  }
}
```

## 4. Latest Schema

### 4.1 语义

`content.latest.json` 表示最近一次确认后的稳定快照，保存完整节点内容。

补充说明：

- `latest.version` 应为整数。
- 若尚未创建任何人工 version，可使用 `0`。

### 4.2 结构

```json
{
  "contentId": "content_xxx",
  "state": "latest",
  "version": 12,
  "label": "latest",
  "nodes": [
    {
      "nodeId": 101,
      "uuid": "node_txt_1",
      "version": 0,
      "kind": "text",
      "text": "hello",
      "meta": {}
    },
    {
      "nodeId": 205,
      "uuid": "node_file_1",
      "version": 0,
      "kind": "file",
      "file": {
        "filename": "demo.png",
        "bucket": "content-assets",
        "objectKey": "path/to/object",
        "mimeType": "image/png",
        "sizeBytes": 1024,
        "checksum": "sha256:..."
      }
    }
  ]
}
```

## 5. Version Schema

### 5.1 语义

`content.<version>.json` 表示不可变历史快照，结构与 latest 基本相同，但 `state=version` 且 `version` 必填。

补充说明：

- JSON 内部的 `version` 是纯整数。
- 文件名中的 `<version>` 应格式化为 6 位零填充数字，例如 `content.000012.json`。

### 5.2 结构

```json
{
  "contentId": "content_xxx",
  "state": "version",
  "version": 12,
  "label": "release-candidate",
  "nodes": [
    {
      "nodeId": 101,
      "uuid": "node_txt_1",
      "version": 0,
      "kind": "text",
      "text": "hello",
      "meta": {}
    }
  ]
}
```

## 6. 完整节点项 Schema

### 6.1 Text Node Snapshot

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["nodeId", "uuid", "version", "kind", "text"],
  "properties": {
    "nodeId": {
      "type": "integer",
      "minimum": 1
    },
    "uuid": {
      "type": "string",
      "minLength": 1
    },
    "version": {
      "type": "integer",
      "minimum": 0
    },
    "kind": {
      "const": "text"
    },
    "text": {
      "type": "string"
    },
    "meta": {
      "type": "object"
    }
  }
}
```

### 6.2 File Node Snapshot

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["nodeId", "uuid", "version", "kind", "file"],
  "properties": {
    "nodeId": {
      "type": "integer",
      "minimum": 1
    },
    "uuid": {
      "type": "string",
      "minLength": 1
    },
    "version": {
      "type": "integer",
      "minimum": 0
    },
    "kind": {
      "const": "file"
    },
    "file": {
      "type": "object",
      "additionalProperties": false,
      "required": ["filename", "bucket", "objectKey"],
      "properties": {
        "filename": {
          "type": "string"
        },
        "bucket": {
          "type": "string"
        },
        "objectKey": {
          "type": "string"
        },
        "mimeType": {
          "type": "string"
        },
        "sizeBytes": {
          "type": "integer",
          "minimum": 0
        },
        "checksum": {
          "type": "string"
        },
        "meta": {
          "type": "object"
        }
      }
    }
  }
}
```

## 7. Latest / Version JSON Schema

`latest` 和 `version` 可以共享一套主体结构，通过 `state` 和 `version` 做差异化约束。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "content.snapshot.schema.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["contentId", "state", "version", "nodes"],
  "properties": {
    "contentId": {
      "type": "string",
      "minLength": 1
    },
    "state": {
      "enum": ["latest", "version"]
    },
    "version": {
      "type": "integer",
      "minimum": 0
    },
    "label": {
      "type": "string"
    },
    "nodes": {
      "type": "array",
      "items": {
        "oneOf": [
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["nodeId", "uuid", "version", "kind", "text"],
            "properties": {
              "nodeId": { "type": "integer", "minimum": 1 },
              "uuid": { "type": "string", "minLength": 1 },
              "version": { "type": "integer", "minimum": 0 },
              "kind": { "const": "text" },
              "text": { "type": "string" },
              "meta": { "type": "object" }
            }
          },
          {
            "type": "object",
            "additionalProperties": false,
            "required": ["nodeId", "uuid", "version", "kind", "file"],
            "properties": {
              "nodeId": { "type": "integer", "minimum": 1 },
              "uuid": { "type": "string", "minLength": 1 },
              "version": { "type": "integer", "minimum": 0 },
              "kind": { "const": "file" },
              "file": {
                "type": "object",
                "additionalProperties": false,
                "required": ["filename", "bucket", "objectKey"],
                "properties": {
                  "filename": { "type": "string" },
                  "bucket": { "type": "string" },
                  "objectKey": { "type": "string" },
                  "mimeType": { "type": "string" },
                  "sizeBytes": { "type": "integer", "minimum": 0 },
                  "checksum": { "type": "string" },
                  "meta": { "type": "object" }
                }
              }
            }
          }
        ]
      }
    }
  }
}
```

## 8. 建议校验规则

- `draft.nodes[*].nodeId` 必须都能在数据库中找到
- `latest/version.nodes[*].nodeId` 可保留为生成快照时的源节点 ID，但读取不应依赖数据库
- `latest/version` 中的 `uuid + version` 应与生成快照时的 Node 一致
- `version` 文件创建后禁止修改
- `latest` 可被下一次 commit 覆盖
- rollback 时应优先按 `nodeId` 恢复，失败后退化为按 `uuid + version` 恢复
