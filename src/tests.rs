//! Golden fixtures from `fixtures/gen` (npm compact-encoding, hypercore,
//! protomux): every case must decode to the JS value and re-encode to the
//! identical bytes.

use super::hypercore::*;
use super::protomux::*;
use super::*;
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

trait ToJson {
    fn json(&self) -> Value;
}

macro_rules! num_json {
    ($($t:ty),*) => {$(impl ToJson for $t { fn json(&self) -> Value { json!(*self) } })*};
}
num_json!(u8, u16, u32, u64, i8, i16, i32, i64, bool);

impl ToJson for String {
    fn json(&self) -> Value {
        json!(self)
    }
}
impl ToJson for Bytes {
    fn json(&self) -> Value {
        json!(hex(self))
    }
}
impl<const N: usize> ToJson for [u8; N] {
    fn json(&self) -> Value {
        json!(hex(self))
    }
}
impl<T: ToJson> ToJson for Vec<T> {
    fn json(&self) -> Value {
        Value::Array(self.iter().map(ToJson::json).collect())
    }
}
impl<T: ToJson> ToJson for Option<T> {
    fn json(&self) -> Value {
        self.as_ref().map_or(Value::Null, ToJson::json)
    }
}
impl ToJson for HashAlgo {
    fn json(&self) -> Value {
        json!("blake2b")
    }
}
impl ToJson for SignatureAlgo {
    fn json(&self) -> Value {
        json!("ed25519")
    }
}

macro_rules! struct_json {
    ($t:ty { $($field:ident => $name:literal),+ }) => {
        impl ToJson for $t {
            fn json(&self) -> Value {
                let mut m = serde_json::Map::new();
                $(m.insert($name.into(), self.$field.json());)+
                Value::Object(m)
            }
        }
    };
}

struct_json!(Signer { signature => "signature", namespace => "namespace", public_key => "publicKey" });
struct_json!(Prologue { hash => "hash", length => "length" });
struct_json!(Manifest {
    version => "version", hash => "hash", allow_patch => "allowPatch", quorum => "quorum",
    signers => "signers", prologue => "prologue", linked => "linked", user_data => "userData"
});
struct_json!(Node { index => "index", size => "size", hash => "hash" });
struct_json!(Handshake { seeks => "seeks", capability => "capability" });
struct_json!(RequestBlock { index => "index", nodes => "nodes" });
struct_json!(RequestSeek { bytes => "bytes", padding => "padding" });
struct_json!(RequestUpgrade { start => "start", length => "length" });
struct_json!(Request {
    id => "id", fork => "fork", block => "block", hash => "hash", seek => "seek",
    upgrade => "upgrade", manifest => "manifest", priority => "priority"
});
struct_json!(Cancel { request => "request" });
struct_json!(DataBlock { index => "index", value => "value", nodes => "nodes" });
struct_json!(DataHash { index => "index", nodes => "nodes" });
struct_json!(DataSeek { bytes => "bytes", nodes => "nodes" });
struct_json!(DataUpgrade {
    start => "start", length => "length", nodes => "nodes",
    additional_nodes => "additionalNodes", signature => "signature"
});
struct_json!(Data {
    request => "request", fork => "fork", block => "block", hash => "hash", seek => "seek",
    upgrade => "upgrade", manifest => "manifest"
});
struct_json!(NoData { request => "request", reason => "reason" });
struct_json!(Want { start => "start", length => "length", any => "any" });
struct_json!(Range { drop => "drop", start => "start", length => "length" });
struct_json!(Bitfield { start => "start", bitfield => "bitfield" });
struct_json!(Sync {
    fork => "fork", length => "length", remote_length => "remoteLength",
    can_upgrade => "canUpgrade", uploading => "uploading", downloading => "downloading",
    has_manifest => "hasManifest", allow_push => "allowPush"
});
struct_json!(ReorgHint { from => "from", to => "to", ancestors => "ancestors" });
struct_json!(Extension { name => "name", message => "message" });
struct_json!(MultisigInput { signer => "signer", signature => "signature", patch => "patch" });
struct_json!(PatchV0 { start => "start", length => "length", nodes => "nodes" });
struct_json!(MultisigInputV0 { signer => "signer", signature => "signature", patch => "patch" });
struct_json!(MultiSignatureV1 { proofs => "proofs", patch => "patch" });
struct_json!(MultiSignatureV0 { proofs => "proofs", patch => "patch" });
struct_json!(Open { local_id => "localId", protocol => "protocol", id => "id", handshake => "handshake" });
struct_json!(ChannelRef { id => "id" });

/// Node prints IPv6 as eight unpadded lowercase groups, never compressed.
fn ipv6_json(ip: &Ipv6Addr) -> Value {
    json!(
        ip.segments()
            .iter()
            .map(|s| format!("{s:x}"))
            .collect::<Vec<_>>()
            .join(":")
    )
}

fn ip_json(ip: &IpAddr) -> Value {
    match ip {
        IpAddr::V4(a) => json!(a.to_string()),
        IpAddr::V6(a) => ipv6_json(a),
    }
}

fn addr_json(a: &SocketAddr) -> Value {
    json!({ "host": ip_json(&a.ip()), "family": if a.is_ipv4() { 4 } else { 6 }, "port": a.port() })
}

fn reader(b: &[u8]) -> Reader {
    Reader::new(Bytes::copy_from_slice(b))
}

/// Decodes `bytes`, returning its JSON form and its re-encoding.
fn run(codec: &str, bytes: &[u8]) -> (Value, Vec<u8>) {
    fn codec_case<T: Codec + ToJson>(b: &[u8]) -> (Value, Vec<u8>) {
        let v: T = decode(Bytes::copy_from_slice(b)).unwrap();
        (v.json(), encode(&v).to_vec())
    }
    macro_rules! prim {
        ($read:ident, $write:ident) => {{
            let v = reader(bytes).$read().unwrap();
            let mut w = Writer::new();
            w.$write(v);
            (v.json(), w.into_vec())
        }};
        ($read:ident, $write:ident, $json:expr) => {{
            let v = reader(bytes).$read().unwrap();
            let mut w = Writer::new();
            w.$write(&v);
            (($json)(&v), w.into_vec())
        }};
    }
    match codec {
        "uint" => prim!(uint, uint),
        "uint8" => prim!(uint8, uint8),
        "uint16" => prim!(uint16, uint16),
        "uint24" => prim!(uint24, uint24),
        "uint32" => prim!(uint32, uint32),
        "uint32be" => prim!(uint32be, uint32be),
        "uint40" => prim!(uint40, uint40),
        "uint48" => prim!(uint48, uint48),
        "uint56" => prim!(uint56, uint56),
        "uint64" => prim!(uint64, uint64),
        "uint64be" => prim!(uint64be, uint64be),
        "int" => prim!(int, int),
        "int8" => prim!(int8, int8),
        "int16" => prim!(int16, int16),
        "int32" => prim!(int32, int32),
        "int64" => prim!(int64, int64),
        "float32" => {
            let v = reader(bytes).float32().unwrap();
            let mut w = Writer::new();
            w.float32(v);
            (json!(v as f64), w.into_vec())
        }
        "float64" => {
            let v = reader(bytes).float64().unwrap();
            let mut w = Writer::new();
            w.float64(v);
            (json!(v), w.into_vec())
        }
        "bool" => prim!(bool, bool),
        "buffer" => codec_case::<Bytes>(bytes),
        "optionalBuffer" => {
            let v = reader(bytes).optional_buffer().unwrap();
            let mut w = Writer::new();
            w.optional_buffer(v.as_deref());
            (v.json(), w.into_vec())
        }
        "raw" => {
            let v = reader(bytes).raw();
            (v.json(), v.to_vec())
        }
        "string" => codec_case::<String>(bytes),
        "fixed32" => codec_case::<[u8; 32]>(bytes),
        "fixed64" => codec_case::<[u8; 64]>(bytes),
        "uint32array" => prim!(uint32array, uint32array, |v: &Vec<u32>| v.json()),
        "bitarray" => prim!(bitarray, bitarray, |v: &Vec<bool>| v.json()),
        "array(uint)" => codec_case::<Vec<u64>>(bytes),
        "array(string)" => codec_case::<Vec<String>>(bytes),
        "frame(string)" => prim!(frame, frame, |v: &String| v.json()),
        "frame(uint)" => prim!(frame, frame, |v: &u64| v.json()),
        "ipv4" => prim!(ipv4, ipv4, |v: &std::net::Ipv4Addr| json!(v.to_string())),
        "ipv6" => prim!(ipv6, ipv6, ipv6_json),
        "ip" => prim!(ip, ip, ip_json),
        "ipAddress" => prim!(ip_address, ip_address, addr_json),
        "manifest" => codec_case::<Manifest>(bytes),
        "handshake" => codec_case::<Handshake>(bytes),
        "request" => codec_case::<Request>(bytes),
        "cancel" => codec_case::<Cancel>(bytes),
        "data" => codec_case::<Data>(bytes),
        "noData" => codec_case::<NoData>(bytes),
        "want" | "unwant" => codec_case::<Want>(bytes),
        "range" => codec_case::<Range>(bytes),
        "bitfield" => codec_case::<Bitfield>(bytes),
        "sync" => codec_case::<Sync>(bytes),
        "reorgHint" => codec_case::<ReorgHint>(bytes),
        "extension" => codec_case::<Extension>(bytes),
        "multiSignature" => codec_case::<MultiSignatureV1>(bytes),
        "multiSignaturev0" => codec_case::<MultiSignatureV0>(bytes),
        "protomuxOpen" => codec_case::<Open>(bytes),
        "protomuxChannelRef" => codec_case::<ChannelRef>(bytes),
        other => panic!("fixture codec without a Rust mapping: {other}"),
    }
}

/// JSON writes integral floats as integers, so compare numbers by value.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| same(a, b))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

#[test]
fn golden_fixtures_round_trip() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("../fixtures/golden.json")).expect("fixture json");
    assert!(cases.len() > 200);
    for case in &cases {
        let codec = case["codec"].as_str().unwrap();
        let bytes = unhex(case["hex"].as_str().unwrap());
        let (value, reencoded) = run(codec, &bytes);
        assert!(
            same(&value, &case["value"]),
            "{codec}: decoded {value} != {}",
            case["value"]
        );
        assert_eq!(hex(&reencoded), hex(&bytes), "{codec}: re-encoding differs");
    }
}

#[test]
fn truncated_input_is_an_error_not_a_panic() {
    assert_eq!(reader(&[0xfe, 1, 2]).uint(), Err(Error::OutOfBounds));
    assert_eq!(reader(&[3, 1]).buffer(), Err(Error::OutOfBounds));
    // A huge length prefix must fail before allocating.
    assert_eq!(
        reader(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).uint32array(),
        Err(Error::OutOfBounds)
    );
    let cases: Vec<Value> = serde_json::from_str(include_str!("../fixtures/golden.json")).unwrap();
    for case in cases.iter().filter(|c| {
        ["manifest", "request", "data", "multiSignature"].contains(&c["codec"].as_str().unwrap())
    }) {
        let bytes = unhex(case["hex"].as_str().unwrap());
        for cut in 0..bytes.len() {
            let prefix = Bytes::copy_from_slice(&bytes[..cut]);
            let failed = match case["codec"].as_str().unwrap() {
                "manifest" => decode::<Manifest>(prefix).is_err(),
                "request" => decode::<Request>(prefix).is_err(),
                "data" => decode::<Data>(prefix).is_err(),
                _ => decode::<MultiSignatureV1>(prefix).is_err(),
            };
            assert!(failed, "{} decoded from a {cut}-byte prefix", case["codec"]);
        }
    }
}

#[test]
fn array_length_limit_matches_js() {
    let mut w = Writer::new();
    w.uint(MAX_ARRAY_DECODE + 1);
    assert_eq!(
        decode::<Vec<u64>>(w.finish()),
        Err(Error::ArrayTooBig(MAX_ARRAY_DECODE + 1))
    );
}

#[test]
fn non_minimal_uint_is_accepted_like_js() {
    assert_eq!(reader(&[0xfd, 5, 0]).uint(), Ok(5));
    assert_eq!(reader(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]).uint(), Ok(1));
}
