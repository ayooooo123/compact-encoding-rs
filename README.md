# compact-encoding-rs

Rust port of [compact-encoding](https://github.com/holepunchto/compact-encoding), byte-compatible
with the npm package, plus the struct codecs that Hypercore 11 and Protomux put on the wire.

```rust
use compact_encoding::{decode, encode, hypercore::Request, hypercore::RequestBlock};

let req = Request { id: 1, block: Some(RequestBlock { index: 5, nodes: 2 }), ..Default::default() };
let bytes = encode(&req);
assert_eq!(&bytes[..], [1, 1, 0, 5, 2]);
assert_eq!(decode::<Request>(bytes).unwrap(), req);
```

- `Writer` / `Reader`: every primitive (`uint`, fixed-width ints, zig-zag ints, floats, `bool`,
  `buffer`, `optionalBuffer`, `raw`, `string`, `fixed(n)`, `uint32array`, `bitarray`, `array`,
  `frame`, `ipv4`/`ipv6`/`ip`/`ipAddress`).
- `Codec`: positional encoding for a type. Implemented for `u64` (uint), `bool`, `String`,
  `Bytes` (buffer), `[u8; N]` (fixed) and `Vec<T>` (array).
- `hypercore`: manifests (v0 and v1–3), tree nodes, every replication wire message, and the
  multisig proof formats.
- `protomux`: the control-channel bodies (open, reject, close).

Decoding reads from `bytes::Bytes`, so buffer fields are zero-copy slices of the input. As in JS,
decoders accept non-minimal uints, ignore trailing bytes and treat any `bool` byte other than `1`
as `false`.

Not ported: `json`, `ndjson`, `any`, `date`, `biguint`/`bigint`, `lexint` and the non-UTF-8
string encodings. Hypercore's oplog/storage codecs are left out on purpose: storage is private to
each peer.

## Compatibility

`fixtures/golden.json` holds 200+ cases encoded by the npm reference (`compact-encoding` 3.5.2,
`hypercore` 11.40.3, `protomux` 3.13.0). `cargo test` decodes every case to
the JS value and re-encodes it to identical bytes. Regenerate with:

```sh
cd fixtures/gen && npm install && npm run gen
```

## License

MIT OR Apache-2.0
