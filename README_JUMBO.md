# Super Jumbo Record Size Limit (TLS 1.3)

## Short Description

The Super Jumbo Record Size Limit extension enables TLS 1.3 peers to negotiate
record payload limits well beyond the classic 16 KB boundary. This can reduce
record fragmentation and improve efficiency for large application transfers.

This branch implements the extension for TLS 1.3 in wolfSSL and includes
interoperability testing against an mbedTLS implementation.

## Specification

Implementation target:

- `draft-ietf-tls-super-jumbo-record-limit-03`

Key points from draft-03:

- Extension type: `100` (`large_record_size_limit` / `jumbo`)
- Extension payload format: fixed `uint32` (4 bytes)
- Valid value range: `64` to `2^30 - 256`
- Negotiation flow:
  - Client advertises extension in `ClientHello`
  - Server confirms in `EncryptedExtensions`
  - Negotiated value limits inbound `TLSInnerPlaintext` from the peer

Important distinction:

- Extension payload uses fixed `uint32`.
- TLSLargeCiphertext record framing uses `varuint` for record length after
  successful negotiation.

## Code Extension Summary

The implementation in this repository adds:

- TLS 1.3 extension write/parse handling for type `100`
- Context/session state for:
  - locally configured jumbo receive limit
  - peer-advertised jumbo receive limit
- Negotiated jumbo limit enforcement in record send/receive paths
- Configurable record size behavior (not hard-limited to `16384`)

## Build

From `wolfssl_jumbo/`:

```bash
cmake -S . -B build \
  -DWOLFSSL_TLS13=ON \
  -DWOLFSSL_EXAMPLES=OFF \
  -DWOLFSSL_CRYPT_TESTS=OFF \
  -DCMAKE_C_FLAGS="-DWOLFSSL_MAX_RECORD_SIZE=65535"

cmake --build build -j
```

## Test (wolfSSL <-> mbedTLS Interop)

From repository root (`super_jumbo/`):

```bash
LIMIT=65535 PAYLOAD=50000 ./run_wolfssl_mbedtls_jumbo_interop.sh
```

Expected summary:

- `[TEST1] OK`
- `[TEST2] OK`
- `[PASS] Interop tests succeeded`

Logs are written to:

- `/tmp/jumbo_interop_work`

## References

- mbedTLS jumbo branch:
  - https://github.com/hannestschofenig/mbedtls/tree/jumbo
- mbedTLS jumbo README:
  - https://github.com/hannestschofenig/mbedtls/blob/jumbo/README_JUMBO.md
