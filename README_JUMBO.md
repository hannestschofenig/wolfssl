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


## Functionality and interoperability status

This is an experimental TLS 1.3 over TCP implementation targeting
[draft-ietf-tls-super-jumbo-record-limit-03](https://datatracker.ietf.org/doc/html/draft-ietf-tls-super-jumbo-record-limit-03).
Client and server roles support negotiation in ClientHello and
EncryptedExtensions using the implementation's extension code point 100.
The extension value is a four-byte network-order uint32. Each endpoint
advertises its own receive limit independently; it covers TLSInnerPlaintext,
including content type and padding, and excludes AEAD expansion.

The draft permits limits from 64 through 2^30 - 256 bytes. This protocol
range does not imply that the implementation can buffer records of every
such size. Build-time buffer limits also apply. In particular, wolfSSL's
WOLFSSL_MAX_RECORD_SIZE setting currently permits 128 through 65535 bytes.

After negotiation, application-traffic records use TLSLargeCiphertext with
canonical 1-, 2-, or 4-byte varuint lengths. Handshake and early-traffic
records retain their standard TLS framing. TLS oversized records and invalid
Jumbo length encodings require a fatal record_overflow alert.

Previously successful cross-library tests covered both client/server role
combinations with a 65535-byte advertised limit and 50000-byte application
transfers. These tests do not establish full draft conformance. DTLS,
cross-library resumption, 0-RTT, and KeyUpdate are outside the verified
interoperability coverage. Mbed TLS additionally has local Jumbo test cases
for small records, length boundaries, and session resumption; their presence
does not establish cross-library support.

### Record overflow regression tests

After building both libraries with the interoperability script, run from the
parent `super_jumbo` directory:

```sh
python3 run_jumbo_overflow_tests.py
```

`WOLF_BUILD` and `MBED_BUILD` select the CMake build directories (defaults:
`/tmp/wolfssl_jumbo_build` and `/tmp/mbedtls_jumbo_build`). The tests require a
C compiler and localhost TCP sockets. Logs are retained in a temporary directory
printed by the runner. `JUMBO_TEST_PORT` overrides the default port 44550.

For both servers, the tests check an exact-limit valid record, an authenticated
record one byte over the limit, the reserved length prefix, non-minimal two- and
four-byte lengths, and oversized header-only records. The peer verifies a fatal
`record_overflow` alert (22); header-only cases also check that the receiver does
not wait for the payload. Different advertised limits exercise the direction of
the receive limit.
