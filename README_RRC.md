# Return Routability Check (RRC) in wolfSSL

## Overview

This directory contains a client-side implementation of **Return Routability Check (RRC)** for DTLS 1.2 with Connection ID (CID), based on RFC 9853.

In this setup, wolfSSL is used as a DTLS client and interoperates with the Californium/Scandium RRC server implementation.

## What Is Implemented

- RRC extension support in the DTLS handshake (client-side usage)
- RRC message handling for:
  - `path_challenge`
  - `path_response`
- CID dependency handling (`RRC` requires `DTLS CID`)
- Example client:
  - `examples/client/dtls_rrc_client.c`

## Build and Run (Short)

Build:

```bash
cd wolfssl
cmake -S . -B build-rrc \
  -DCMAKE_BUILD_TYPE=Debug \
  -DWOLFSSL_DTLS=yes \
  -DWOLFSSL_DTLS13=yes \
  -DWOLFSSL_DTLS_CID=yes \
  -DWOLFSSL_DTLS_CID_RRC=yes \
  -DWOLFSSL_PSK=yes \
  -DWOLFSSL_DEBUG=yes
cmake --build build-rrc --target dtls_rrc_client -j
```

Run client (against NAT on `127.0.0.1:6684`):

```bash
./build-rrc/examples/client/dtls_rrc_client 127.0.0.1 6684
```

## Notes

- The client prefers AEAD suites first and enables CID+RRC before handshake.
- A successful run should show that RRC was negotiated and that the client can respond to a `path_challenge`.

## Full Documentation

For the complete end-to-end setup (Californium server, NAT, Thomas Fossati client, Mbed TLS client, wolfSSL client, logs, troubleshooting), see:

- Repository: `https://github.com/hannestschofenig/mbedtls`
- Branch: `rrc`
- File: `README_RRC.md`

