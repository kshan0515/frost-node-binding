use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::BTreeMap;
use frost_ed25519 as frost;
use frost::keys::dkg::{round1, round2, part1, part2, part3};
use frost::Identifier;
use rand::rngs::OsRng;

// bincode를 사용하여 직렬화/역직렬화하는 헬퍼 함수
fn to_bincode<T: serde::Serialize>(val: &T) -> Result<Vec<u8>> {
    bincode::serialize(val).map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))
}

fn from_bincode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T> {
    bincode::deserialize(buf).map_err(|e| Error::new(Status::GenericFailure, format!("역직렬화 오류: {}", e)))
}

#[napi]
pub struct FrostDkgState {
    // 내부 상태를 저장할 수도 있지만, JS쪽에서 관리하도록 직렬화된 데이터를 주고받는 방식(Stateless)이
    // 오케스트레이터의 세션 관리와 더 잘 맞을 수 있습니다.
}

#[napi]
impl FrostDkgState {
    /// DKG 1단계: Round 1 패키지(Commitment) 생성
    /// { secret_package, round1_package } 반환 (둘 다 bincode로 직렬화됨)
    #[napi]
    pub fn dkg_part1(
        party_id: u16,
        max_signers: u16,
        min_signers: u16,
    ) -> Result<DkgPart1Output> {
        let mut rng = OsRng;
        let identifier = Identifier::try_from(party_id).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
        
        let (secret_package, round1_package) = part1(identifier, max_signers, min_signers, &mut rng)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        Ok(DkgPart1Output {
            secret_package: to_bincode(&secret_package)?,
            round1_package: to_bincode(&round1_package)?,
        })
    }

    /// DKG 2단계: Round 2 패키지(Secret Shares) 생성
    /// 입력: secret_package (1단계), round1_packages (party_id -> package 맵)
    /// 반환: { secret_package, round2_packages_map }
    #[napi]
    pub fn dkg_part2(
        secret_package_bin: Vec<u8>,
        round1_packages_map: BTreeMap<String, Vec<u8>>,
    ) -> Result<DkgPart2Output> {
        let secret_package: round1::SecretPackage = from_bincode(&secret_package_bin)?;
        
        let mut round1_packages = BTreeMap::new();
        for (pid_str, pkg_bin) in round1_packages_map {
            let pid = pid_str.parse::<u16>().map_err(|_| Error::new(Status::InvalidArg, "파티 ID는 u16이어야 합니다"))?;
            let identifier = Identifier::try_from(pid).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
            let pkg: round1::Package = from_bincode(&pkg_bin)?;
            round1_packages.insert(identifier, pkg);
        }

        let (secret_package_r2, round2_packages) = part2(secret_package, &round1_packages)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        let mut round2_packages_out = BTreeMap::new();
        for (id, pkg) in round2_packages {
            round2_packages_out.insert(serialize_identifier(&id)?, to_bincode(&pkg)?);
        }

        Ok(DkgPart2Output {
            secret_package: to_bincode(&secret_package_r2)?,
            round2_packages: round2_packages_out,
        })
    }

    /// DKG 3단계: 최종 완료
    #[napi]
    pub fn dkg_part3(
        secret_package_bin: Vec<u8>,
        round1_packages_map: BTreeMap<String, Vec<u8>>,
        round2_packages_map: BTreeMap<String, Vec<u8>>,
    ) -> Result<DkgPart3Output> {
        let secret_package: round2::SecretPackage = from_bincode(&secret_package_bin)?;

        let mut round1_packages = BTreeMap::new();
        for (pid_str, pkg_bin) in round1_packages_map {
            let pid = pid_str.parse::<u16>().map_err(|_| Error::new(Status::InvalidArg, "파티 ID는 u16이어야 합니다"))?;
            let identifier = Identifier::try_from(pid).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
            let pkg: round1::Package = from_bincode(&pkg_bin)?;
            round1_packages.insert(identifier, pkg);
        }

        let mut round2_packages = BTreeMap::new();
        for (pid_str, pkg_bin) in round2_packages_map {
            let pid = pid_str.parse::<u16>().map_err(|_| Error::new(Status::InvalidArg, "파티 ID는 u16이어야 합니다"))?;
            let identifier = Identifier::try_from(pid).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
            let pkg: round2::Package = from_bincode(&pkg_bin)?;
            round2_packages.insert(identifier, pkg);
        }

        let (key_package, pubkey_package) = part3(&secret_package, &round1_packages, &round2_packages)
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        Ok(DkgPart3Output {
            key_package: to_bincode(&key_package)?,
            pubkey_package: to_bincode(&pubkey_package)?,
        })
    }

    /// PublicKeyPackage에서 공개키 바이트(32바이트)를 추출하는 헬퍼 함수
    #[napi]
    pub fn get_public_key_bytes(pubkey_package_bin: Vec<u8>) -> Result<Vec<u8>> {
        let pubkey_package: frost::keys::PublicKeyPackage = from_bincode(&pubkey_package_bin)?;
        let group_public = pubkey_package.verifying_key(); // VerifyingKey
        let bytes = group_public.serialize()
            .map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;
        Ok(bytes.to_vec())
    }

    /// 주어진 파티 ID에 대한 직렬화된 식별자(hex)를 가져오는 헬퍼 함수
    #[napi]
    pub fn get_identifier(party_id: u16) -> Result<String> {
        let identifier = Identifier::try_from(party_id).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
        serialize_identifier(&identifier)
    }
}

#[napi(object)]
pub struct DkgPart1Output {
    pub secret_package: Vec<u8>,
    pub round1_package: Vec<u8>,
}

#[napi(object)]
pub struct DkgPart2Output {
    pub secret_package: Vec<u8>,
    // 키는 직렬화된 Identifier(JS 객체 키로 사용하기 위해 String 사용)
    pub round2_packages: BTreeMap<String, Vec<u8>>, 
}

#[napi(object)]
pub struct DkgPart3Output {
    pub key_package: Vec<u8>,
    pub pubkey_package: Vec<u8>,
}

// JS 맵 키를 위해 Identifier의 문자열 표현을 얻는 헬퍼 함수
fn serialize_identifier(id: &Identifier) -> Result<String> {
    let bytes = bincode::serialize(id).map_err(|_| Error::from_status(Status::GenericFailure))?;
    Ok(hex::encode(bytes))
}
