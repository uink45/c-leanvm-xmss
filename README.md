# c-leanvm-xmss

C bindings for leanVM/leanMultisig XMSS signatures and aggregation.

## Scope

- XMSS key generation, signing, verification
- SSZ serialization/deserialization for public keys and signatures
- Postcard serialization/deserialization for secret keys
- LeanVM aggregation setup, raw aggregation, recursive aggregation, and verification

The API mirrors `c-hash-sig` where possible to keep integration minimal.

## Build

```bash
cargo build --release
```

Outputs:
- Static library: `target/release/libleanvm_xmss_c.a`
- Dynamic library: `target/release/libleanvm_xmss_c.{so,dylib,dll}`
- Header: `include/leanvm-xmss.h`

A compatibility header is provided at `include/pq-bindings-c-rust.h`.

## leanVM Main Notes

- XMSS public keys are 32 bytes.
- XMSS signatures are 1208 bytes in canonical SSZ form.
- `pq_signature_deserialize` and `pq_verify_ssz` accept zero-padded signature buffers.

## Aggregated Proof Encoding

`pq_aggregate_signatures` and `pq_aggregate_signatures_recursive` return leanVM
main's postcard encoding without public keys.

`pq_verify_aggregated_signatures` expects this exact encoding.

## Notes

- Message length must be exactly 32 bytes (SSZ hash tree root).
- Use `pq_xmss_aggregation_setup_prover` / `pq_xmss_aggregation_setup_verifier`
  once at startup to avoid first-call latency.
- `pq_aggregate_signatures_recursive` accepts child proofs plus raw XMSS signatures so
  callers can build recursive proofs without flattening them first.
