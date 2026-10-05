# BGZF 归档审计服务

在随机访问归档入库前核对 BGZF 压缩数据与配套块偏移索引，防止损坏成员或偏移漂移
使后续区间读取落到错误位置。

## 接口

### `POST /api/bgzf/audit`（`multipart/form-data`）

| 字段 | 内容 |
| --- | --- |
| `archive` | BGZF 压缩归档，不超过 **8 MiB**，数据块不超过 **4096** 个 |
| `index` | 小端 `uint64` 偏移对索引：每个**非首数据块**一对 `(compressed_offset, uncompressed_offset)`，共 `16 × (块数-1)` 字节；单块归档时为空文件 |

**成功 `200`**（原子返回，校验全过后才有响应体）：

```json
{
  "block_count": 3,
  "uncompressed_size": 785,
  "sha256": "4135b6…"
}
```

`sha256` 针对**全部成员解压后拼接的字节流**计算。

**失败 `422`**（不返回任何部分结果）：

```json
{ "error": { "code": "CRC32_MISMATCH", "message": "…", "offset": 35 } }
```

`offset` 是首个可定位的**压缩文件偏移**（成员起点；索引错误时为索引所指向的压缩偏移），
归档人员可据此判断重传数据还是重建索引。

### 校验规则

- 每个成员为完整 gzip(RFC 1952) 成员：magic、CM=deflate；FEXTRA 中**恰有一个 BC 子字段**
- BSIZE 声明块长与实际可用字节一致；raw Deflate 流必须恰好结束于 BSIZE 所声明的尾部边界
- CRC32、ISIZE 与解压数据一致
- 归档末尾**恰有一个**标准 28 字节空 EOF 成员，其后不得有任何字节
- 索引逐项等于各非首块的压缩起点及累计解压起点（小端 u64）

### 稳定错误码

`EMPTY_ARCHIVE`、`ARCHIVE_TOO_LARGE`、`TRUNCATED_MEMBER`、
`MALFORMED_MEMBER_HEADER`、`UNSUPPORTED_MEMBER_FLAGS`、`MALFORMED_EXTRA_HEADER`、
`MISSING_BC_SUBFIELD`、`DUPLICATE_BC_SUBFIELD`、`BSIZE_OUT_OF_RANGE`、
`BLOCK_SIZE_MISMATCH`、`DEFLATE_BOUNDARY_MISMATCH`、`CRC32_MISMATCH`、
`ISIZE_MISMATCH`、`MISSING_EOF_MEMBER`、`INVALID_EOF_MEMBER`、
`BYTES_AFTER_EOF_MEMBER`、`TOO_MANY_DATA_BLOCKS`、`INDEX_TOO_LARGE`、
`INDEX_LENGTH_MISMATCH`、`INDEX_COMPRESSED_OFFSET_MISMATCH`、
`INDEX_UNCOMPRESSED_OFFSET_MISMATCH`、`MALFORMED_REQUEST`、`UPLOAD_TOO_LARGE`。

另有 `GET /health` 供健康检查。

## 运行

```bash
# 端口映射可由环境变量调整（容器内监听 PORT，默认 8080）
APP_PORT=9000 docker compose up --build app

# 一次性验证服务：等待 app 健康后运行 pytest、compileall 构建检查，
# 并提交 合法归档 / CRC / 块长 / 索引错位 四类冒烟样例，按退出码结束
docker compose up --build verify
docker compose rm -f verify   # 确认其退出码后清理
```

## 本地开发

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest                       # 30 项单元 + HTTP 测试
uvicorn app.main:app --port 8080      # 另开终端
BASE_URL=http://127.0.0.1:8080 python scripts/smoke.py
```

## 目录

```
app/bgzf.py       纯标准库校验核心（成员解析 / EOF / 索引）
app/main.py       FastAPI 路由、统一错误体、健康检查
app/samples.py    确定性 BGZF 样例构造器（仅供测试/冒烟）
tests/            单元与 HTTP 测试
scripts/smoke.py  四类端到端冒烟提交
scripts/verify.sh verify 服务入口（pytest + compileall + smoke）
Dockerfile        含 HEALTHCHECK，端口由 PORT 控制
docker-compose.yml app（APP_PORT 映射）+ 依赖健康的一次性 verify
```
