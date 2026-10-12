use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::BTreeMap;
use frost_ed25519 as frost;
use frost::{round1, round2, SigningPackage, Identifier};
use rand::rngs::OsRng;
use zeroize::Zeroize;
use crate::executor::ZeroizableNonces;

// bincode를 사용하여 직렬화/역직렬화하는 헬퍼 함수
fn to_bincode<T: serde::Serialize>(val: &T) -> Result<Buffer> {
    let bytes = bincode::serialize(val).map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))?;
    Ok(Buffer::from(bytes))
}

fn from_bincode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T> {
    bincode::deserialize(buf).map_err(|e| Error::new(Status::GenericFailure, format!("역직렬화 오류: {}", e)))
}

fn parse_party_identifier(s: &str) -> Result<Identifier> {
    if let Ok(pid) = s.parse::<u16>() {
        return Identifier::try_from(pid).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)));
    }
    if let Ok(bytes) = hex::decode(s) {
        if let Ok(id) = bincode::deserialize::<Identifier>(&bytes) {
            return Ok(id);
        }
    }
    Err(Error::new(Status::InvalidArg, format!("파티 ID는 u16 또는 hex 식별자여야 합니다: {}", s)))
}

#[napi]
pub struct FrostSigningState {}

#[napi]
impl FrostSigningState {
    /// 서명 1단계: Preprocessing (Nonce 생성)
    /// 입력: key_package (bincode)
    /// 반환: { nonces (Secret), commitments (Public) }
    #[napi]
    pub fn sign_part1(key_package_bin: Buffer) -> Result<SignPart1Output> {
        let key_package: frost::keys::KeyPackage = from_bincode(key_package_bin.as_ref())?;
        let mut rng = OsRng;

        let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);

        Ok(SignPart1Output {
            nonces: to_bincode(&nonces)?,
            commitments: to_bincode(&commitments)?,
        })
    }

    /// 서명 1단계 (External 핸들): V8 힙 격리를 위한 핸들 기반 Nonce 생성
    #[napi]
    pub fn sign_part1_handle(key_package: External<frost::keys::KeyPackage>) -> Result<SignPart1HandleOutput> {
        let mut rng = OsRng;
        let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);
        Ok(SignPart1HandleOutput {
            nonces: External::new(ZeroizableNonces(nonces)),
            commitments: to_bincode(&commitments)?,
        })
    }

    /// 서명 2단계: 부분 서명 생성 (Partial Sign)
    /// 입력: signing_package (Public), nonces (Secret), key_package (Secret)
    /// 반환: signature_share
    #[napi]
    pub fn sign_part2(
        signing_package_bin: Buffer,
        nonces_bin: Buffer,
        key_package_bin: Buffer,
    ) -> Result<Buffer> {
        let signing_package: SigningPackage = from_bincode(signing_package_bin.as_ref())?;
        let mut nonces: round1::SigningNonces = from_bincode(nonces_bin.as_ref())?;
        let mut key_package: frost::keys::KeyPackage = from_bincode(key_package_bin.as_ref())?;

        let signature_share = round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)));

        // Nonce 및 장기 키 서명 쉐어 메모리 제로화 파기
        nonces.zeroize();
        key_package.zeroize();

        let sig = signature_share?;
        to_bincode(&sig)
    }

    /// 서명 2단계 (External 핸들): V8 힙 격리 핸들을 이용한 부분 서명 생성
    #[napi]
    pub fn sign_part2_handle(
        signing_package_bin: Buffer,
        mut nonces: External<ZeroizableNonces>,
        key_package: External<frost::keys::KeyPackage>,
    ) -> Result<Buffer> {
        let signing_package: SigningPackage = from_bincode(signing_package_bin.as_ref())?;
        let signature_share = round2::sign(&signing_package, &nonces.0, &key_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        // 1회용 Nonce 즉시 제로화
        nonces.zeroize();
        to_bincode(&signature_share)
    }

    /// 메시지와 Commitments 맵으로부터 SigningPackage를 생성하는 헬퍼 함수
    #[napi]
    pub fn create_signing_package(
        message: Buffer,
        commitments_map: BTreeMap<String, Buffer>,
    ) -> Result<Buffer> {
        let mut map = BTreeMap::new();
        for (pid_str, comm_bin) in commitments_map {
            let identifier = parse_party_identifier(&pid_str)?;
            let comm: round1::SigningCommitments = from_bincode(comm_bin.as_ref())?;
            map.insert(identifier, comm);
        }

        let package = SigningPackage::new(map, message.as_ref());
        to_bincode(&package)
    }

    /// 서명 조각들을 합쳐서 최종 서명 생성 (Aggregate)
    #[napi]
    pub fn aggregate(
        signing_package_bin: Buffer,
        signature_shares_map: BTreeMap<String, Buffer>,
        pubkey_package_bin: Buffer,
    ) -> Result<Buffer> {
        let signing_package: SigningPackage = from_bincode(signing_package_bin.as_ref())?;
        let pubkey_package: frost::keys::PublicKeyPackage = from_bincode(pubkey_package_bin.as_ref())?;

        let mut shares = BTreeMap::new();
        for (pid_str, share_bin) in signature_shares_map {
            let identifier = parse_party_identifier(&pid_str)?;
            let share: round2::SignatureShare = from_bincode(share_bin.as_ref())?;
            shares.insert(identifier, share);
        }

        let signature = frost::aggregate(&signing_package, &shares, &pubkey_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        // 최종 서명(Ed25519 표준 64바이트: R || s) 반환
        let signature_bytes = signature.serialize()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;
        Ok(Buffer::from(signature_bytes.to_vec()))
    }
}

#[napi(object)]
pub struct SignPart1Output {
    pub nonces: Buffer,
    pub commitments: Buffer,
}

#[napi(object)]
pub struct SignPart1HandleOutput {
    pub nonces: External<ZeroizableNonces>,
    pub commitments: Buffer,
}
