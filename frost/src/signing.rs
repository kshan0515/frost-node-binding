use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::BTreeMap;
use frost_ed25519 as frost;
use frost::{round1, round2, SigningPackage, Identifier};
use rand::rngs::OsRng;

// bincode를 사용하여 직렬화/역직렬화하는 헬퍼 함수
fn to_bincode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>> {
    bincode::serialize(val).map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))
}

fn from_bincode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T> {
    bincode::deserialize(buf).map_err(|e| Error::new(Status::GenericFailure, format!("역직렬화 오류: {}", e)))
}

#[napi]
pub struct FrostSigningState {}

#[napi]
impl FrostSigningState {
    /// 서명 1단계: Preprocessing (Nonce 생성)
    /// 입력: key_package (bincode)
    /// 반환: { nonces (Secret), commitments (Public) }
    #[napi]
    pub fn sign_part1(key_package_bin: Vec<u8>) -> Result<SignPart1Output> {
        let key_package: frost::keys::KeyPackage = from_bincode(&key_package_bin)?;
        let mut rng = OsRng;

        let (nonces, commitments) = round1::commit(key_package.signing_share(), &mut rng);

        Ok(SignPart1Output {
            nonces: to_bincode(&nonces)?,
            commitments: to_bincode(&commitments)?,
        })
    }

    /// 서명 2단계: 부분 서명 생성 (Partial Sign)
    /// 입력: signing_package (Public), nonces (Secret), key_package (Secret)
    /// 반환: signature_share
    #[napi]
    pub fn sign_part2(
        signing_package_bin: Vec<u8>,
        nonces_bin: Vec<u8>,
        key_package_bin: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let signing_package: SigningPackage = from_bincode(&signing_package_bin)?;
        let nonces: round1::SigningNonces = from_bincode(&nonces_bin)?;
        let key_package: frost::keys::KeyPackage = from_bincode(&key_package_bin)?;

        let signature_share = round2::sign(&signing_package, &nonces, &key_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        to_bincode(&signature_share)
    }

    /// 메시지와 Commitments 맵으로부터 SigningPackage를 생성하는 헬퍼 함수
    #[napi]
    pub fn create_signing_package(
        message: Vec<u8>,
        commitments_map: BTreeMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut map = BTreeMap::new();
        for (pid_str, comm_bin) in commitments_map {
            let pid_u16 = pid_str.parse::<u16>().map_err(|_| Error::new(Status::InvalidArg, "파티 ID는 u16이어야 합니다"))?;
            let identifier = Identifier::try_from(pid_u16).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
            
            let comm: round1::SigningCommitments = from_bincode(&comm_bin)?;
            map.insert(identifier, comm);
        }

        let package = SigningPackage::new(map, &message);
        to_bincode(&package)
    }

    /// 서명 조각들을 합쳐서 최종 서명 생성 (Aggregate)
    #[napi]
    pub fn aggregate(
        signing_package_bin: Vec<u8>,
        signature_shares_map: BTreeMap<String, Vec<u8>>,
        pubkey_package_bin: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let signing_package: SigningPackage = from_bincode(&signing_package_bin)?;
        let pubkey_package: frost::keys::PublicKeyPackage = from_bincode(&pubkey_package_bin)?;

        let mut shares = BTreeMap::new();
        for (pid_str, share_bin) in signature_shares_map {
            let pid_u16 = pid_str.parse::<u16>().map_err(|_| Error::new(Status::InvalidArg, "파티 ID는 u16이어야 합니다"))?;
            let identifier = Identifier::try_from(pid_u16).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
            
            let share: round2::SignatureShare = from_bincode(&share_bin)?;
            shares.insert(identifier, share);
        }

        let signature = frost::aggregate(&signing_package, &shares, &pubkey_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        // 최종 서명(Ed25519 표준 64바이트: R || s) 반환
        // bincode 직렬화 대신 표준 직렬화 방식 사용
        let signature_bytes = signature.serialize()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;
        Ok(signature_bytes.to_vec())
    }
}

#[napi(object)]
pub struct SignPart1Output {
    pub nonces: Vec<u8>,
    pub commitments: Vec<u8>,
}
