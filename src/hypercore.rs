//! Hypercore 11 wire messages, manifests and multisig proofs, as encoded by
//! `hypercore/lib/messages.js`. Oplog/storage codecs are not here: storage is
//! private to each peer.

use crate::{
    Bytes, Codec, Error, Reader, Result, Writer, array_len, buffer_len, optional_buffer_len,
    uint_len,
};

const MANIFEST_PATCH: u64 = 1;
const MANIFEST_PROLOGUE: u64 = 2;
const MANIFEST_LINKED: u64 = 4;
const MANIFEST_USER_DATA: u64 = 8;

/// Tree hash function. Only `blake2b` (id 0) exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgo {
    #[default]
    Blake2b,
}

impl Codec for HashAlgo {
    fn encoded_len(&self) -> usize {
        1
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(0)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match r.uint()? {
            0 => Ok(HashAlgo::Blake2b),
            n => Err(Error::Invalid("Unknown hash id", n)),
        }
    }
}

/// Signature scheme. Only `ed25519` (id 0) exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgo {
    #[default]
    Ed25519,
}

impl Codec for SignatureAlgo {
    fn encoded_len(&self) -> usize {
        1
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(0)
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        match r.uint()? {
            0 => Ok(SignatureAlgo::Ed25519),
            n => Err(Error::Invalid("Unknown signature id", n)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub signature: SignatureAlgo,
    pub namespace: [u8; 32],
    pub public_key: [u8; 32],
}

impl Codec for Signer {
    fn encoded_len(&self) -> usize {
        1 + 32 + 32
    }
    fn encode(&self, w: &mut Writer) {
        self.signature.encode(w);
        w.raw(&self.namespace);
        w.raw(&self.public_key);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            signature: Codec::decode(r)?,
            namespace: r.fixed()?,
            public_key: r.fixed()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prologue {
    pub hash: [u8; 32],
    pub length: u64,
}

impl Codec for Prologue {
    fn encoded_len(&self) -> usize {
        32 + uint_len(self.length)
    }
    fn encode(&self, w: &mut Writer) {
        w.raw(&self.hash);
        w.uint(self.length);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            hash: r.fixed()?,
            length: r.uint()?,
        })
    }
}

/// A core manifest. `version == 0` uses the compact legacy layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    pub hash: HashAlgo,
    pub allow_patch: bool,
    pub quorum: u64,
    pub signers: Vec<Signer>,
    pub prologue: Option<Prologue>,
    pub linked: Option<Vec<[u8; 32]>>,
    pub user_data: Option<Bytes>,
}

impl Manifest {
    fn v0_prologue_only(&self) -> Option<&Prologue> {
        self.prologue.as_ref().filter(|_| self.signers.is_empty())
    }

    fn v0_single_signer(&self) -> bool {
        self.quorum == 1 && self.signers.len() == 1 && !self.allow_patch
    }
}

impl Codec for Manifest {
    fn encoded_len(&self) -> usize {
        // version, hash, type/flags are all single-byte uints
        if self.version == 0 {
            return 3 + if self.v0_prologue_only().is_some() {
                32
            } else if self.v0_single_signer() {
                self.signers[0].encoded_len()
            } else {
                1 + uint_len(self.quorum) + array_len(&self.signers)
            };
        }
        3 + uint_len(self.quorum)
            + array_len(&self.signers)
            + self.prologue.as_ref().map_or(0, Codec::encoded_len)
            + self.linked.as_ref().map_or(0, |l| array_len(l))
            + self.user_data.as_ref().map_or(0, |u| buffer_len(u.len()))
    }

    fn encode(&self, w: &mut Writer) {
        w.uint(self.version);
        if self.version == 0 {
            self.hash.encode(w);
            if let Some(p) = self.v0_prologue_only() {
                w.uint(0);
                w.raw(&p.hash);
            } else if self.v0_single_signer() {
                w.uint(1);
                self.signers[0].encode(w);
            } else {
                w.uint(2);
                w.uint(self.allow_patch as u64);
                w.uint(self.quorum);
                w.array(&self.signers);
            }
            return;
        }
        let flags = if self.allow_patch { MANIFEST_PATCH } else { 0 }
            | if self.prologue.is_some() {
                MANIFEST_PROLOGUE
            } else {
                0
            }
            | if self.linked.is_some() {
                MANIFEST_LINKED
            } else {
                0
            }
            | if self.user_data.is_some() {
                MANIFEST_USER_DATA
            } else {
                0
            };
        w.uint(flags);
        self.hash.encode(w);
        w.uint(self.quorum);
        w.array(&self.signers);
        if let Some(p) = &self.prologue {
            p.encode(w)
        }
        if let Some(l) = &self.linked {
            w.array(l)
        }
        if let Some(u) = &self.user_data {
            w.buffer(u)
        }
    }

    fn decode(r: &mut Reader) -> Result<Self> {
        let version = r.uint()?;
        if version == 0 {
            let hash = Codec::decode(r)?;
            let base = Self {
                version: 0,
                hash,
                allow_patch: false,
                quorum: 0,
                signers: vec![],
                prologue: None,
                linked: None,
                user_data: None,
            };
            return match r.uint()? {
                0 => Ok(Self {
                    prologue: Some(Prologue {
                        hash: r.fixed()?,
                        length: 0,
                    }),
                    ..base
                }),
                1 => Ok(Self {
                    quorum: 1,
                    signers: vec![Codec::decode(r)?],
                    ..base
                }),
                2 => {
                    let flags = r.uint()?;
                    Ok(Self {
                        allow_patch: flags & 1 != 0,
                        quorum: r.uint()?,
                        signers: r.array()?,
                        ..base
                    })
                }
                t => Err(Error::Invalid("Unknown type", t)),
            };
        }
        if version > 3 {
            return Err(Error::Invalid("Unknown version", version));
        }
        let flags = r.uint()?;
        Ok(Self {
            version,
            hash: Codec::decode(r)?,
            quorum: r.uint()?,
            signers: r.array()?,
            allow_patch: flags & MANIFEST_PATCH != 0,
            prologue: if flags & MANIFEST_PROLOGUE != 0 {
                Some(Codec::decode(r)?)
            } else {
                None
            },
            linked: if flags & MANIFEST_LINKED != 0 {
                Some(r.array()?)
            } else {
                None
            },
            user_data: if flags & MANIFEST_USER_DATA != 0 {
                Some(r.buffer()?)
            } else {
                None
            },
        })
    }
}

/// A merkle tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub index: u64,
    pub size: u64,
    pub hash: [u8; 32],
}

impl Codec for Node {
    fn encoded_len(&self) -> usize {
        uint_len(self.index) + uint_len(self.size) + 32
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.index);
        w.uint(self.size);
        w.raw(&self.hash);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            index: r.uint()?,
            size: r.uint()?,
            hash: r.fixed()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub seeks: bool,
    pub capability: [u8; 32],
}

impl Codec for Handshake {
    fn encoded_len(&self) -> usize {
        1 + 32
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.seeks as u64);
        w.raw(&self.capability);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            seeks: flags & 1 != 0,
            capability: r.fixed()?,
        })
    }
}

macro_rules! uint_struct {
    ($(#[$m:meta])* $name:ident { $($field:ident),+ }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct $name { $(pub $field: u64),+ }

        impl Codec for $name {
            fn encoded_len(&self) -> usize {
                0 $(+ uint_len(self.$field))+
            }
            fn encode(&self, w: &mut Writer) {
                $(w.uint(self.$field);)+
            }
            fn decode(r: &mut Reader) -> Result<Self> {
                Ok(Self { $($field: r.uint()?),+ })
            }
        }
    };
}

uint_struct!(
    /// Used for both `block` and `hash` requests.
    RequestBlock { index, nodes }
);
uint_struct!(RequestSeek { bytes, padding });
uint_struct!(RequestUpgrade { start, length });
uint_struct!(Cancel { request });
uint_struct!(ReorgHint {
    from,
    to,
    ancestors
});

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    pub id: u64,
    pub fork: u64,
    pub block: Option<RequestBlock>,
    pub hash: Option<RequestBlock>,
    pub seek: Option<RequestSeek>,
    pub upgrade: Option<RequestUpgrade>,
    pub manifest: bool,
    /// Zero means "no priority" and is not put on the wire.
    pub priority: u64,
}

fn opt_len<T: Codec>(v: &Option<T>) -> usize {
    v.as_ref().map_or(0, Codec::encoded_len)
}

fn opt_enc<T: Codec>(v: &Option<T>, w: &mut Writer) {
    if let Some(v) = v {
        v.encode(w)
    }
}

fn opt_dec<T: Codec>(flags: u64, bit: u64, r: &mut Reader) -> Result<Option<T>> {
    if flags & bit != 0 {
        T::decode(r).map(Some)
    } else {
        Ok(None)
    }
}

impl Codec for Request {
    fn encoded_len(&self) -> usize {
        1 + uint_len(self.id)
            + uint_len(self.fork)
            + opt_len(&self.block)
            + opt_len(&self.hash)
            + opt_len(&self.seek)
            + opt_len(&self.upgrade)
            + if self.priority != 0 {
                uint_len(self.priority)
            } else {
                0
            }
    }
    fn encode(&self, w: &mut Writer) {
        let flags = self.block.is_some() as u64
            | (self.hash.is_some() as u64) << 1
            | (self.seek.is_some() as u64) << 2
            | (self.upgrade.is_some() as u64) << 3
            | (self.manifest as u64) << 4
            | ((self.priority != 0) as u64) << 5;
        w.uint(flags);
        w.uint(self.id);
        w.uint(self.fork);
        opt_enc(&self.block, w);
        opt_enc(&self.hash, w);
        opt_enc(&self.seek, w);
        opt_enc(&self.upgrade, w);
        if self.priority != 0 {
            w.uint(self.priority)
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            id: r.uint()?,
            fork: r.uint()?,
            block: opt_dec(flags, 1, r)?,
            hash: opt_dec(flags, 2, r)?,
            seek: opt_dec(flags, 4, r)?,
            upgrade: opt_dec(flags, 8, r)?,
            manifest: flags & 16 != 0,
            priority: if flags & 32 != 0 { r.uint()? } else { 0 },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataUpgrade {
    pub start: u64,
    pub length: u64,
    pub nodes: Vec<Node>,
    pub additional_nodes: Vec<Node>,
    pub signature: Option<Bytes>,
}

impl Codec for DataUpgrade {
    fn encoded_len(&self) -> usize {
        uint_len(self.start)
            + uint_len(self.length)
            + array_len(&self.nodes)
            + array_len(&self.additional_nodes)
            + optional_buffer_len(self.signature.as_deref())
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.start);
        w.uint(self.length);
        w.array(&self.nodes);
        w.array(&self.additional_nodes);
        w.optional_buffer(self.signature.as_deref());
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            start: r.uint()?,
            length: r.uint()?,
            nodes: r.array()?,
            additional_nodes: r.array()?,
            signature: r.optional_buffer()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataSeek {
    pub bytes: u64,
    pub nodes: Vec<Node>,
}

impl Codec for DataSeek {
    fn encoded_len(&self) -> usize {
        uint_len(self.bytes) + array_len(&self.nodes)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.bytes);
        w.array(&self.nodes);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            bytes: r.uint()?,
            nodes: r.array()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataBlock {
    pub index: u64,
    pub value: Bytes,
    pub nodes: Vec<Node>,
}

impl Codec for DataBlock {
    fn encoded_len(&self) -> usize {
        uint_len(self.index) + buffer_len(self.value.len()) + array_len(&self.nodes)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.index);
        w.buffer(&self.value);
        w.array(&self.nodes);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            index: r.uint()?,
            value: r.buffer()?,
            nodes: r.array()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataHash {
    pub index: u64,
    pub nodes: Vec<Node>,
}

impl Codec for DataHash {
    fn encoded_len(&self) -> usize {
        uint_len(self.index) + array_len(&self.nodes)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.index);
        w.array(&self.nodes);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            index: r.uint()?,
            nodes: r.array()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Data {
    pub request: u64,
    pub fork: u64,
    pub block: Option<DataBlock>,
    pub hash: Option<DataHash>,
    pub seek: Option<DataSeek>,
    pub upgrade: Option<DataUpgrade>,
    pub manifest: Option<Manifest>,
}

impl Codec for Data {
    fn encoded_len(&self) -> usize {
        1 + uint_len(self.request)
            + uint_len(self.fork)
            + opt_len(&self.block)
            + opt_len(&self.hash)
            + opt_len(&self.seek)
            + opt_len(&self.upgrade)
            + opt_len(&self.manifest)
    }
    fn encode(&self, w: &mut Writer) {
        let flags = self.block.is_some() as u64
            | (self.hash.is_some() as u64) << 1
            | (self.seek.is_some() as u64) << 2
            | (self.upgrade.is_some() as u64) << 3
            | (self.manifest.is_some() as u64) << 4;
        w.uint(flags);
        w.uint(self.request);
        w.uint(self.fork);
        opt_enc(&self.block, w);
        opt_enc(&self.hash, w);
        opt_enc(&self.seek, w);
        opt_enc(&self.upgrade, w);
        opt_enc(&self.manifest, w);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            request: r.uint()?,
            fork: r.uint()?,
            block: opt_dec(flags, 1, r)?,
            hash: opt_dec(flags, 2, r)?,
            seek: opt_dec(flags, 4, r)?,
            upgrade: opt_dec(flags, 8, r)?,
            manifest: opt_dec(flags, 16, r)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoData {
    pub request: u64,
    /// Zero means "no reason" and is not put on the wire.
    pub reason: u64,
}

impl Codec for NoData {
    fn encoded_len(&self) -> usize {
        uint_len(self.request)
            + 1
            + if self.reason != 0 {
                uint_len(self.reason)
            } else {
                0
            }
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.request);
        w.uint((self.reason != 0) as u64);
        if self.reason != 0 {
            w.uint(self.reason)
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let request = r.uint()?;
        let flags = if r.is_empty() { 0 } else { r.uint()? };
        Ok(Self {
            request,
            reason: if flags & 1 != 0 { r.uint()? } else { 0 },
        })
    }
}

/// Body of both `want` and `unwant`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Want {
    pub start: u64,
    pub length: u64,
    pub any: bool,
}

pub type Unwant = Want;

impl Codec for Want {
    fn encoded_len(&self) -> usize {
        uint_len(self.start) + uint_len(self.length) + self.any as usize
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.start);
        w.uint(self.length);
        if self.any {
            w.uint(1)
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let start = r.uint()?;
        let length = r.uint()?;
        let flags = if r.is_empty() { 0 } else { r.uint()? };
        Ok(Self {
            start,
            length,
            any: flags & 1 != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Range {
    pub drop: bool,
    pub start: u64,
    pub length: u64,
}

impl Codec for Range {
    fn encoded_len(&self) -> usize {
        1 + uint_len(self.start)
            + if self.length != 1 {
                uint_len(self.length)
            } else {
                0
            }
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.drop as u64 | ((self.length == 1) as u64) << 1);
        w.uint(self.start);
        if self.length != 1 {
            w.uint(self.length)
        }
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            drop: flags & 1 != 0,
            start: r.uint()?,
            length: if flags & 2 != 0 { 1 } else { r.uint()? },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bitfield {
    pub start: u64,
    /// Little-endian 32-bit words.
    pub bitfield: Vec<u32>,
}

impl Codec for Bitfield {
    fn encoded_len(&self) -> usize {
        uint_len(self.start) + uint_len(self.bitfield.len() as u64) + 4 * self.bitfield.len()
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.start);
        w.uint32array(&self.bitfield);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            start: r.uint()?,
            bitfield: r.uint32array()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sync {
    pub fork: u64,
    pub length: u64,
    pub remote_length: u64,
    pub can_upgrade: bool,
    pub uploading: bool,
    pub downloading: bool,
    pub has_manifest: bool,
    pub allow_push: bool,
}

impl Codec for Sync {
    fn encoded_len(&self) -> usize {
        1 + uint_len(self.fork) + uint_len(self.length) + uint_len(self.remote_length)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(
            self.can_upgrade as u64
                | (self.uploading as u64) << 1
                | (self.downloading as u64) << 2
                | (self.has_manifest as u64) << 3
                | (self.allow_push as u64) << 4,
        );
        w.uint(self.fork);
        w.uint(self.length);
        w.uint(self.remote_length);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            fork: r.uint()?,
            length: r.uint()?,
            remote_length: r.uint()?,
            can_upgrade: flags & 1 != 0,
            uploading: flags & 2 != 0,
            downloading: flags & 4 != 0,
            has_manifest: flags & 8 != 0,
            allow_push: flags & 16 != 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extension {
    pub name: String,
    /// Raw remainder of the frame.
    pub message: Bytes,
}

impl Codec for Extension {
    fn encoded_len(&self) -> usize {
        buffer_len(self.name.len()) + self.message.len()
    }
    fn encode(&self, w: &mut Writer) {
        w.string(&self.name);
        w.raw(&self.message);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            name: r.string()?,
            message: r.raw(),
        })
    }
}

/// One signer's contribution to a multisig (manifest version >= 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigInput {
    pub signer: u64,
    pub signature: [u8; 64],
    pub patch: u64,
}

impl Codec for MultisigInput {
    fn encoded_len(&self) -> usize {
        uint_len(self.signer) + 64 + uint_len(self.patch)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.signer);
        w.raw(&self.signature);
        w.uint(self.patch);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            signer: r.uint()?,
            signature: r.fixed()?,
            patch: r.uint()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchV0 {
    pub start: u64,
    pub length: u64,
    pub nodes: Vec<u64>,
}

impl Codec for PatchV0 {
    fn encoded_len(&self) -> usize {
        uint_len(self.start) + uint_len(self.length) + array_len(&self.nodes)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.start);
        w.uint(self.length);
        w.array(&self.nodes);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            start: r.uint()?,
            length: r.uint()?,
            nodes: r.array()?,
        })
    }
}

/// Multisig input for manifest version 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigInputV0 {
    pub signer: u64,
    pub signature: [u8; 64],
    pub patch: Option<PatchV0>,
}

impl Codec for MultisigInputV0 {
    fn encoded_len(&self) -> usize {
        1 + uint_len(self.signer) + 64 + opt_len(&self.patch)
    }
    fn encode(&self, w: &mut Writer) {
        w.uint(self.patch.is_some() as u64);
        w.uint(self.signer);
        w.raw(&self.signature);
        opt_enc(&self.patch, w);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        let flags = r.uint()?;
        Ok(Self {
            signer: r.uint()?,
            signature: r.fixed()?,
            patch: opt_dec(flags, 1, r)?,
        })
    }
}

/// The signature field of an upgrade on a quorum (multisig) core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiSignature<I> {
    pub proofs: Vec<I>,
    pub patch: Vec<Node>,
}

pub type MultiSignatureV1 = MultiSignature<MultisigInput>;
pub type MultiSignatureV0 = MultiSignature<MultisigInputV0>;

impl<I: Codec> Codec for MultiSignature<I> {
    fn encoded_len(&self) -> usize {
        array_len(&self.proofs) + array_len(&self.patch)
    }
    fn encode(&self, w: &mut Writer) {
        w.array(&self.proofs);
        w.array(&self.patch);
    }
    fn decode(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            proofs: r.array()?,
            patch: r.array()?,
        })
    }
}
