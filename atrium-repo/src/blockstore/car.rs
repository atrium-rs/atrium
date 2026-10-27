use std::{collections::HashMap, convert::Infallible};

use ipld_core::cid::{Cid, multihash::Multihash};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt as _,
    SeekFrom,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::blockstore::{self, AsyncBlockStoreRead, SHA2_256};

use super::AsyncBlockStoreWrite;

#[derive(Debug, Serialize, Deserialize)]
pub struct V1Header {
    pub version: u64,
    pub roots: Vec<Cid>,
}

/// Check a length the CAR declares for itself against the bytes actually
/// left after `at`, before anything is allocated for it.
fn fits(declared: u64, at: u64, end: u64) -> Result<(), Error> {
    let remaining = end.saturating_sub(at);
    if declared > remaining {
        return Err(Error::LengthExceedsData { declared, remaining });
    }
    Ok(())
}

/// An indexed reader/writer for CAR files.
#[derive(Debug)]
pub struct CarStore<S: AsyncRead + AsyncSeek> {
    storage: S,
    header: V1Header,
    index: HashMap<Cid, (u64, usize)>,
}

impl<R: AsyncRead + AsyncSeek + Unpin> CarStore<R> {
    /// Open a pre-existing CAR file.
    ///
    /// Every length the CAR declares is checked against the bytes actually
    /// present before it is allocated, and every block must be hashed with
    /// SHA-256 (the only hash an atproto repo allows) and match its CID. So a
    /// malformed or hostile CAR is an error, rather than a panic, an
    /// out-of-memory kill, or a block stored under a CID it does not hash to.
    ///
    /// The storage must support `SeekFrom::End`, and its length is read once,
    /// at the start. Bytes appended after that are rejected as
    /// [`Error::LengthExceedsData`] rather than indexed.
    pub async fn open(mut storage: R) -> Result<Self, Error> {
        let begin = storage.stream_position().await?;
        let end = storage.seek(SeekFrom::End(0)).await?;
        storage.seek(SeekFrom::Start(begin)).await?;

        // Read the header.
        let header_len = unsigned_varint::aio::read_usize((&mut storage).compat()).await?;
        fits(header_len as u64, storage.stream_position().await?, end)?;
        let mut header_bytes = vec![0; header_len];
        storage.read_exact(&mut header_bytes).await?;
        let header: V1Header = serde_ipld_dagcbor::from_slice(&header_bytes)?;

        let mut section = Vec::new();

        // Build the index. The CAR ends exactly at `end`, so a section length
        // cut off partway through is an error rather than a clean finish.
        let mut index = HashMap::new();
        while storage.stream_position().await? < end {
            let data_len = unsigned_varint::aio::read_u64((&mut storage).compat()).await?;
            let start = storage.stream_position().await?;
            fits(data_len, start, end)?;

            section.resize(data_len as usize, 0);
            storage.read_exact(section.as_mut_slice()).await?;

            // The CID is read from inside the section, so it cannot run past it.
            let mut block = section.as_slice();
            let cid = Cid::read_bytes(&mut block)?;
            let cid_len = section.len() - block.len();

            let code = cid.hash().code();
            if code != SHA2_256 {
                return Err(Error::UnsupportedHash(code));
            }
            if cid.hash().digest() != sha2::Sha256::digest(block).as_slice() {
                return Err(Error::InvalidHash);
            }

            index.insert(cid, (start + cid_len as u64, block.len()));
        }

        Ok(Self { storage, header, index })
    }

    pub fn roots(&self) -> impl Iterator<Item = Cid> {
        self.header.roots.clone().into_iter()
    }
}

impl<S: AsyncRead + AsyncWrite + AsyncSeek + Send + Unpin> CarStore<S> {
    pub async fn create(storage: S) -> Result<Self, Error> {
        Self::create_with_roots(storage, []).await
    }

    pub async fn create_with_roots(
        mut storage: S,
        roots: impl IntoIterator<Item = Cid>,
    ) -> Result<Self, Error> {
        let header = V1Header { version: 1, roots: roots.into_iter().collect::<Vec<_>>() };

        let header_bytes = serde_ipld_dagcbor::to_vec(&header).unwrap();
        let mut buf = unsigned_varint::encode::usize_buffer();
        let buf = unsigned_varint::encode::usize(header_bytes.len(), &mut buf);
        storage.write_all(buf).await?;
        storage.write_all(&header_bytes).await?;

        Ok(Self { storage, header, index: HashMap::new() })
    }
}

impl<R: AsyncRead + AsyncSeek + Send + Unpin> AsyncBlockStoreRead for CarStore<R> {
    async fn read_block_into(
        &mut self,
        cid: Cid,
        contents: &mut Vec<u8>,
    ) -> Result<(), blockstore::Error> {
        contents.clear();

        let (offset, len) = self.index.get(&cid).ok_or_else(|| blockstore::Error::CidNotFound)?;
        contents.resize(*len, 0);

        self.storage.seek(SeekFrom::Start(*offset)).await?;
        self.storage.read_exact(contents).await?;

        Ok(())
    }
}

impl<R: AsyncRead + AsyncWrite + AsyncSeek + Send + Unpin> AsyncBlockStoreWrite for CarStore<R> {
    async fn write_block(
        &mut self,
        codec: u64,
        hash: u64,
        contents: &[u8],
    ) -> Result<Cid, blockstore::Error> {
        let digest = match hash {
            SHA2_256 => sha2::Sha256::digest(contents),
            _ => return Err(blockstore::Error::UnsupportedHash(hash)),
        };
        let hash =
            Multihash::wrap(hash, digest.as_slice()).expect("internal error encoding multihash");
        let cid = Cid::new_v1(codec, hash);

        // Only write the record if the CAR file does not already contain it.
        if let std::collections::hash_map::Entry::Vacant(e) = self.index.entry(cid) {
            let mut fc = vec![];
            cid.write_bytes(&mut fc).expect("internal error writing CID");

            let mut buf = unsigned_varint::encode::u64_buffer();
            let buf = unsigned_varint::encode::u64((fc.len() + contents.len()) as u64, &mut buf);

            self.storage.seek(SeekFrom::End(0)).await?;
            self.storage.write_all(buf).await?;
            self.storage.write_all(&fc).await?;
            let offs = self.storage.stream_position().await?;
            self.storage.write_all(contents).await?;

            // Update the index with the new block.
            e.insert((offs, contents.len()));
        }

        Ok(cid)
    }
}

/// Errors that can occur while interacting with a CAR.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid CID: {0}")]
    Cid(#[from] ipld_core::cid::Error),
    #[error("CID does not exist in CAR")]
    CidNotFound,
    #[error("file hash does not match computed hash for block")]
    InvalidHash,
    #[error("invalid explicit CID v0")]
    InvalidCidV0,
    #[error("invalid varint: {0}")]
    InvalidVarint(#[from] unsigned_varint::io::ReadError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Multihash: {0}")]
    Multihash(#[from] ipld_core::cid::multihash::Error),
    #[error("serde_ipld_dagcbor decoding error: {0}")]
    Parse(#[from] serde_ipld_dagcbor::DecodeError<Infallible>),
    #[error("declared length {declared} exceeds the {remaining} bytes left in the CAR")]
    LengthExceedsData { declared: u64, remaining: u64 },
    #[error("block hashed with multihash code {0:#x}; only SHA-256 is allowed")]
    UnsupportedHash(u64),
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::blockstore::{DAG_CBOR, MemoryBlockStore};

    use super::*;

    #[tokio::test]
    async fn basic_rw() {
        const STR: &[u8] = b"the quick brown fox jumps over the lazy dog";

        let mut mem = Vec::new();
        let mut bs = CarStore::create(Cursor::new(&mut mem)).await.unwrap();

        let cid = bs.write_block(DAG_CBOR, SHA2_256, STR).await.unwrap();
        assert_eq!(bs.read_block(cid).await.unwrap(), STR);

        let mut bs = CarStore::open(Cursor::new(&mut mem)).await.unwrap();
        assert_eq!(bs.read_block(cid).await.unwrap(), STR);
    }

    #[tokio::test]
    async fn basic_rw_2blocks() {
        const STR1: &[u8] = b"the quick brown fox jumps over the lazy dog";
        const STR2: &[u8] = b"the lazy fox jumps over the quick brown dog";

        let mut mem = Vec::new();
        let mut bs = CarStore::create(Cursor::new(&mut mem)).await.unwrap();

        let cid1 = bs.write_block(DAG_CBOR, SHA2_256, STR1).await.unwrap();
        let cid2 = bs.write_block(DAG_CBOR, SHA2_256, STR2).await.unwrap();
        assert_eq!(bs.read_block(cid1).await.unwrap(), STR1);
        assert_eq!(bs.read_block(cid2).await.unwrap(), STR2);

        let mut bs = CarStore::open(Cursor::new(&mut mem)).await.unwrap();
        assert_eq!(bs.read_block(cid1).await.unwrap(), STR1);
        assert_eq!(bs.read_block(cid2).await.unwrap(), STR2);
    }

    #[tokio::test]
    async fn basic_root() {
        const STR: &[u8] = b"the quick brown fox jumps over the lazy dog";

        let mut mbs = MemoryBlockStore::new();

        let cid = mbs.write_block(DAG_CBOR, SHA2_256, STR).await.unwrap();
        assert_eq!(mbs.read_block(cid).await.unwrap(), STR);

        let mut mem = Vec::new();
        let mut bs = CarStore::create_with_roots(Cursor::new(&mut mem), [cid]).await.unwrap();
        bs.write_block(DAG_CBOR, SHA2_256, STR).await.unwrap();

        assert_eq!(bs.roots().next().unwrap(), cid);
        assert_eq!(bs.read_block(cid).await.unwrap(), STR);

        let mut bs = CarStore::open(Cursor::new(&mut mem)).await.unwrap();
        assert_eq!(bs.roots().next().unwrap(), cid);
        assert_eq!(bs.read_block(cid).await.unwrap(), STR);
    }

    /// A header-only CAR. Tests append sections to it by hand, because
    /// `write_block` cannot write a lie.
    async fn header_only() -> Vec<u8> {
        let mut mem = Vec::new();
        CarStore::create(Cursor::new(&mut mem)).await.unwrap();
        mem
    }

    fn push_varint(car: &mut Vec<u8>, n: u64) {
        let mut buf = unsigned_varint::encode::u64_buffer();
        car.extend_from_slice(unsigned_varint::encode::u64(n, &mut buf));
    }

    /// Append one section: its length, then the CID's bytes, then `data`.
    fn push_section(car: &mut Vec<u8>, cid: &[u8], data: &[u8]) {
        push_varint(car, (cid.len() + data.len()) as u64);
        car.extend_from_slice(cid);
        car.extend_from_slice(data);
    }

    /// A 36-byte CIDv1 (dag-cbor, sha2-256) with an arbitrary digest.
    fn cid_v1_bytes() -> Vec<u8> {
        let mut bytes = vec![0x01, 0x71, 0x12, 0x20];
        bytes.extend_from_slice(&[0xab; 32]);
        bytes
    }

    async fn open(car: Vec<u8>) -> Result<CarStore<Cursor<Vec<u8>>>, Error> {
        CarStore::open(Cursor::new(car)).await
    }

    #[tokio::test]
    async fn section_shorter_than_its_cid_is_refused() {
        // A section declaring 4 bytes, in front of a 36-byte CID. Before the
        // fix, `data_len - cid_len` underflowed and `resize` panicked.
        let mut car = header_only().await;
        push_varint(&mut car, 4);
        car.extend_from_slice(&cid_v1_bytes());
        car.extend_from_slice(&[0; 8]);

        let err = open(car).await.unwrap_err();
        assert!(matches!(err, Error::Cid(_)), "{err:?}");
    }

    #[tokio::test]
    async fn section_longer_than_the_car_is_refused() {
        // Before the fix, `resize` zero-filled the declared 1 TiB.
        let mut car = header_only().await;
        push_varint(&mut car, 1 << 40);
        car.extend_from_slice(&cid_v1_bytes());
        car.extend_from_slice(&[0; 10]);

        let err = open(car).await.unwrap_err();
        assert!(
            matches!(err, Error::LengthExceedsData { declared, remaining: 46 } if declared == 1 << 40),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn header_longer_than_the_car_is_refused() {
        let mut car = Vec::new();
        push_varint(&mut car, 1000);
        car.extend_from_slice(&[0; 5]);

        let err = open(car).await.unwrap_err();
        assert!(
            matches!(err, Error::LengthExceedsData { declared: 1000, remaining: 5 }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn digest_larger_than_a_cid_can_hold_is_refused() {
        for size in [1 << 60, u64::MAX] {
            // CIDv1, dag-cbor, sha2-256, then the declared digest size. Before
            // the fix, `vec![0; prefix + size]` allocated it.
            let mut section = vec![0x01, 0x71, 0x12];
            push_varint(&mut section, size);
            section.extend_from_slice(&[0; 40]);

            let mut car = header_only().await;
            push_varint(&mut car, 40);
            car.extend_from_slice(&section);

            let err = open(car).await.unwrap_err();
            assert!(matches!(err, Error::Cid(_)), "{err:?}");
        }
    }

    #[tokio::test]
    async fn block_under_another_hash_is_refused() {
        // An identity-hash CID: before the fix it was indexed unverified, so
        // it could hold any bytes, including an MST node naming itself.
        let cid = Cid::new_v1(DAG_CBOR, Multihash::wrap(0x00, b"anything").unwrap());
        let mut car = header_only().await;
        push_section(&mut car, &cid.to_bytes(), b"not what the CID says");

        let err = open(car).await.unwrap_err();
        assert!(matches!(err, Error::UnsupportedHash(0x00)), "{err:?}");
    }

    #[tokio::test]
    async fn block_not_matching_its_sha256_cid_is_refused() {
        let mut car = header_only().await;
        push_section(&mut car, &cid_v1_bytes(), b"does not hash to 0xabab..");

        let err = open(car).await.unwrap_err();
        assert!(matches!(err, Error::InvalidHash), "{err:?}");
    }

    #[tokio::test]
    async fn truncated_section_length_is_an_error() {
        // 0x80 starts a varint and never finishes it. Before the fix this read
        // as a clean end of the CAR, and the CAR opened with blocks missing.
        let mut car = header_only().await;
        car.push(0x80);

        let err = open(car).await.unwrap_err();
        assert!(matches!(err, Error::InvalidVarint(_)), "{err:?}");
    }

    #[tokio::test]
    async fn cid_v0_block_opens() {
        // Before the fix, a v0 CID was compared against a rebuilt v1 CID and
        // never matched.
        const DATA: &[u8] = b"the quick brown fox jumps over the lazy dog";
        let digest = Multihash::wrap(SHA2_256, sha2::Sha256::digest(DATA).as_slice()).unwrap();
        let cid = Cid::new_v0(digest).unwrap();

        let mut car = header_only().await;
        push_section(&mut car, &cid.to_bytes(), DATA);

        let mut bs = open(car).await.unwrap();
        assert_eq!(bs.read_block(cid).await.unwrap(), DATA);
    }
}
