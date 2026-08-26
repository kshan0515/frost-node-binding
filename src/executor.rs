use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::BTreeMap;
use frost_ed25519 as frost;
use frost::{Identifier, keys::KeyPackage, keys::PublicKeyPackage};

// 상태 정의
enum ProtocolState {
    Idle,
    DkgRound1(DkgRound1State),
    DkgRound2(DkgRound2State),
    DkgDone(KeyPackage, PublicKeyPackage),
    SigningRound1(SigningRound1State),
    SigningRound2(SigningRound2State),
    Aggregation(AggregationState),
    SigningDone(Vec<u8>), 
}

struct DkgRound1State {
    secret_package: frost::keys::dkg::round1::SecretPackage,
}

struct DkgRound2State {
    secret_package: frost::keys::dkg::round2::SecretPackage,
    round1_packages: BTreeMap<Identifier, frost::keys::dkg::round1::Package>,
}

struct SigningRound1State {
    key_package: KeyPackage,
    message: Vec<u8>,
}

struct SigningRound2State {
    key_package: KeyPackage,
    message: Vec<u8>,
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
    commitments_map: BTreeMap<Identifier, frost::round1::SigningCommitments>,
    signers: Vec<u16>, // 추가: 참여자 목록
}

struct AggregationState {
    signing_package: frost::SigningPackage,
    pubkey_package: PublicKeyPackage,
    signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
    signers: Vec<u16>, // 추가: 참여자 목록
}

#[napi]
pub struct FrostExecutor {
    party_id: u16,
    num_signers: u16,
    threshold: u16,
    state: ProtocolState,
    key_package: Option<KeyPackage>,
    pubkey_package: Option<PublicKeyPackage>,
    id_to_pid: BTreeMap<Identifier, u16>,
}

// Helper to extract u16 from buffer (Big Endian)
fn read_u16(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(Error::new(Status::InvalidArg, "Input buffer too short"));
    }
    let arr: [u8; 2] = buf[0..2].try_into().map_err(|_| Error::new(Status::GenericFailure, "Conversion error"))?;
    Ok(u16::from_be_bytes(arr))
}

#[napi]
impl FrostExecutor {
    #[napi(constructor)]
    pub fn new(party_id: u16, num_signers: u16, threshold: u16) -> Self {
        let mut id_to_pid = BTreeMap::new();
        for i in 1..=num_signers {
            if let Ok(id) = Identifier::try_from(i) {
                id_to_pid.insert(id, i);
            }
        }
        Self {
            party_id,
            num_signers,
            threshold,
            state: ProtocolState::Idle,
            key_package: None,
            pubkey_package: None,
            id_to_pid,
        }
    }

    #[napi]
    pub fn start_keygen(&mut self) -> Result<Buffer> {
        use rand::rngs::OsRng;
        let mut rng = OsRng;
        let identifier = Identifier::try_from(self.party_id)
            .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;

        let (secret_package, round1_package) = frost::keys::dkg::part1(
            identifier,
            self.num_signers,
            self.threshold,
            &mut rng
        ).map_err(|e| Error::new(Status::GenericFailure, format!("{}", e)))?;

        self.state = ProtocolState::DkgRound1(DkgRound1State {
            secret_package,
        });

        // Broadcast: just payload (TS will wrap it)
        let bytes = bincode::serialize(&round1_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))?;
        Ok(Buffer::from(bytes))
    }

    #[napi]
    pub fn start_signing(&mut self, message: Buffer, signers: Option<Vec<u16>>) -> Result<Buffer> {
        let key_package = self.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "키가 없습니다."))?;

        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

        let msg_vec = message.to_vec();
        // 참여자 목록이 없으면 전체가 참여하는 것으로 간주
        let signers_list = signers.unwrap_or_else(|| (1..=self.num_signers).collect());

        self.state = ProtocolState::SigningRound2(SigningRound2State {
            key_package: key_package.clone(),
            message: msg_vec.clone(),
            nonces,
            commitments: commitments.clone(),
            commitments_map: BTreeMap::new(),
            signers: signers_list,
        });

        let bytes = bincode::serialize(&commitments)
            .map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))?;
        Ok(Buffer::from(bytes))
    }

    #[napi]
    pub fn step(&mut self, inputs: Vec<Buffer>) -> Result<Vec<Buffer>> {
        // println!("DEBUG: Party {} step called with {} inputs. State: {:?}", self.party_id, inputs.len(), self.state_name());
        match &mut self.state {
            ProtocolState::DkgRound1(state) => {
                let mut round1_packages = BTreeMap::new();
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];
                    // println!("DEBUG: Party {} processing input from {}", self.party_id, sender_pid);
                    let pkg: frost::keys::dkg::round1::Package = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::GenericFailure, format!("R1 역직렬화 오류: {}", e)))?;
                    
                    let sender_id = Identifier::try_from(sender_pid)
                         .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    round1_packages.insert(sender_id, pkg);
                }

                let (secret_package_r2, round2_packages) = frost::keys::dkg::part2(state.secret_package.clone(), &round1_packages)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("DKG Part 2 오류: {} (inputs: {}, map: {}, max: {})", e, inputs.len(), round1_packages.len(), state.secret_package.max_signers())))?;
                
                self.state = ProtocolState::DkgRound2(DkgRound2State {
                    secret_package: secret_package_r2,
                    round1_packages,
                });

                let mut outputs = Vec::new();
                let my_identifier = Identifier::try_from(self.party_id)
                    .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;

                for (receiver_id, pkg) in round2_packages {
                    if receiver_id == my_identifier {
                        continue; // Skip self
                    }
                    let mut buf = Vec::new();
                    // Get party ID from Identifier
                    let target_pid = *self.id_to_pid.get(&receiver_id).unwrap_or(&0);
                    
                    buf.extend_from_slice(&target_pid.to_be_bytes()); // 2 bytes BE
                    buf.extend_from_slice(&bincode::serialize(&pkg).unwrap());
                    outputs.push(Buffer::from(buf));
                }
                Ok(outputs)
            },
            ProtocolState::DkgRound2(state) => {
                let mut round2_packages = BTreeMap::new();
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];
                    let pkg: frost::keys::dkg::round2::Package = bincode::deserialize(payload)
                         .map_err(|e| Error::new(Status::GenericFailure, format!("R2 역직렬화 오류: {}", e)))?;
                    
                    let sender_id = Identifier::try_from(sender_pid)
                         .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    round2_packages.insert(sender_id, pkg);
                }
                
                let (key_package, pubkey_package) = frost::keys::dkg::part3(
                    &state.secret_package,
                    &state.round1_packages,
                    &round2_packages
                ).map_err(|e| Error::new(Status::GenericFailure, format!("DKG Part 3 오류: {}", e)))?;
                
                self.key_package = Some(key_package.clone());
                self.pubkey_package = Some(pubkey_package.clone());
                self.state = ProtocolState::DkgDone(key_package, pubkey_package);
                Ok(Vec::new())
            },
            ProtocolState::SigningRound2(state) => {
                // Add my commitment
                let my_id = Identifier::try_from(self.party_id)
                    .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                state.commitments_map.insert(my_id, state.commitments.clone());

                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];

                    let comm: frost::round1::SigningCommitments = bincode::deserialize(payload)
                         .map_err(|e| Error::new(Status::GenericFailure, format!("Commitment 역직렬화 오류: {}", e)))?;
                    
                    let sender_id = Identifier::try_from(sender_pid)
                         .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    state.commitments_map.insert(sender_id, comm);
                }
                
                let signing_package = frost::SigningPackage::new(state.commitments_map.clone(), &state.message);
                
                let signature_share = frost::round2::sign(&signing_package, &state.nonces, &state.key_package)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("서명 생성 오류: {}", e)))?;
                
                let mut buf = Vec::new();
                let zero_pid: u16 = 0; // Broadcast
                
                let sig_share_bytes = bincode::serialize(&signature_share).unwrap();
                buf.extend_from_slice(&zero_pid.to_be_bytes());
                buf.extend_from_slice(&sig_share_bytes);
                
                // 나 자신의 서명 조각도 미리 저장 (나중에 aggregate 시 사용)
                let mut signature_shares = BTreeMap::new();
                signature_shares.insert(my_id, signature_share);

                let pubkey_pkg = self.pubkey_package.clone().ok_or_else(|| Error::new(Status::GenericFailure, "No PubKey"))?;
                self.state = ProtocolState::Aggregation(AggregationState {
                    signing_package,
                    pubkey_package: pubkey_pkg,
                    signature_shares, // 내 조각이 포함된 상태로 시작
                    signers: state.signers.clone(),
                });
                
                Ok(vec![Buffer::from(buf)])
            },
            ProtocolState::Aggregation(state) => {
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];
                    let share: frost::round2::SignatureShare = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::GenericFailure, format!("Share 역직렬화 오류: {}", e)))?;
                    
                    let sender_id = Identifier::try_from(sender_pid)
                         .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    state.signature_shares.insert(sender_id, share);
                }

                // 나 자신의 서명 조각도 포함되어야 함 (이미 Aggregator 노드인 경우에도 자기 조각을 가지고 있어야 함)
                // 현재 구조상 모든 노드가 Aggregator 역할을 수행하므로 각 노드는 다른 노드의 조각만 받음.
                // 따라서 나 자신의 조각은 별도로 관리하거나 로직 보완 필요.
                // 일단 Unknown identifier 에러 방지를 위해 state에 나 자신의 조각도 들어있는지 확인 필요.
                
                let signature = frost::aggregate(&state.signing_package, &state.signature_shares, &state.pubkey_package)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("Aggregate 오류: {}", e)))?;

                let sig_bytes = signature.serialize()
                    .map_err(|e| Error::new(Status::GenericFailure, format!("Sig 직렬화 오류: {}", e)))?;
                
                self.state = ProtocolState::SigningDone(sig_bytes);
                Ok(Vec::new())
            }
            _ => Err(Error::new(Status::GenericFailure, "Invalid State")),
        }
    }

    #[napi]
    pub fn get_public_key_bytes(&self) -> Result<Buffer> {
         let pkg = self.pubkey_package.as_ref()
             .ok_or_else(|| Error::new(Status::InvalidArg, "공개키 없음"))?;
         Ok(Buffer::from(pkg.verifying_key().serialize().unwrap().to_vec()))
    }
    
    #[napi]
    pub fn get_signature(&self) -> Result<Buffer> {
        if let ProtocolState::SigningDone(sig) = &self.state {
            Ok(Buffer::from(sig.clone()))
        } else {
             Err(Error::new(Status::GenericFailure, "서명 미완료"))
        }
    }

    #[napi]
    pub fn export_keyshare(&self) -> Result<Buffer> {
        let key = self.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 키가 없습니다."))?;
        let pubkey = self.pubkey_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 공개키 패키지가 없습니다."))?;
        
        let data = (key, pubkey);
        let bytes = bincode::serialize(&data)
            .map_err(|e| Error::new(Status::GenericFailure, format!("키쉐어 직렬화 오류: {}", e)))?;
        Ok(Buffer::from(bytes))
    }

    #[napi]
    pub fn import_keyshare(&mut self, data: Buffer) -> Result<()> {
        let (key, pubkey): (KeyPackage, PublicKeyPackage) = bincode::deserialize(&data)
            .map_err(|e| Error::new(Status::GenericFailure, format!("키쉐어 역직렬화 오류: {}", e)))?;
        
        self.key_package = Some(key.clone());
        self.pubkey_package = Some(pubkey.clone());
        self.state = ProtocolState::DkgDone(key, pubkey);
        Ok(())
    }

    #[napi]
    pub fn get_identifier_bytes(party_id: u16) -> Result<Buffer> {
        let identifier = Identifier::try_from(party_id).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
        Ok(Buffer::from(bincode::serialize(&identifier).unwrap()))
    }
}