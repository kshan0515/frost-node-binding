use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use frost_ed25519 as frost;
use frost::{Identifier, keys::KeyPackage, keys::PublicKeyPackage};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 튜플 구조체인 Newtype 래퍼로 외부 `SigningNonces`를 감싸서 드롭 및 명시적 파기 시 Nonce 메모리를 제로화합니다.
pub struct ZeroizableNonces(pub frost::round1::SigningNonces);

impl Zeroize for ZeroizableNonces {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ZeroizableNonces {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizableNonces {}

impl Clone for ZeroizableNonces {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::ops::Deref for ZeroizableNonces {
    type Target = frost::round1::SigningNonces;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ZeroizableNonces {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// V8 힙 격리를 위한 External 키쉐어 핸들
pub struct FrostKeyShareHandle {
    pub key_package: KeyPackage,
    pub pubkey_package: PublicKeyPackage,
}

// 상태 정의
enum ProtocolState {
    Idle,
    DkgRound1(DkgRound1State),
    DkgRound2(DkgRound2State),
    #[allow(dead_code)]
    DkgDone(KeyPackage, PublicKeyPackage),

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

struct SigningRound2State {
    key_package: KeyPackage,
    message: Vec<u8>,
    nonces: ZeroizableNonces,
    commitments: frost::round1::SigningCommitments,
    commitments_map: BTreeMap<Identifier, frost::round1::SigningCommitments>,
    signers: Option<Vec<u16>>,
}

struct AggregationState {
    signing_package: frost::SigningPackage,
    pubkey_package: PublicKeyPackage,
    signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare>,
    signers: Vec<u16>,
}

pub struct FrostExecutorInner {
    party_id: u16,
    num_signers: u16,
    threshold: u16,
    state: ProtocolState,
    key_package: Option<KeyPackage>,
    pubkey_package: Option<PublicKeyPackage>,
    id_to_pid: BTreeMap<Identifier, u16>,
    is_destroyed: bool,
}

impl FrostExecutorInner {
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
            is_destroyed: false,
        }
    }

    pub fn destroy_internal(&mut self) {
        self.is_destroyed = true;
        if let Some(mut kp) = self.key_package.take() {
            kp.zeroize();
        }
        self.pubkey_package = None;
        match std::mem::replace(&mut self.state, ProtocolState::Idle) {
            ProtocolState::SigningRound2(mut s) => {
                s.nonces.zeroize();
                s.key_package.zeroize();
                s.message.zeroize();
            }
            ProtocolState::SigningDone(mut sig) => {
                sig.zeroize();
            }
            _ => {}
        }
    }

    pub fn start_keygen(&mut self) -> Result<Vec<u8>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
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

        let bytes = bincode::serialize(&round1_package)
            .map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))?;
        Ok(bytes)
    }

    pub fn start_signing(&mut self, message: &[u8], signers: Option<Vec<u16>>) -> Result<Vec<u8>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let key_package = self.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "키가 없습니다."))?;

        let signers_opt = if let Some(ref signers_list) = signers {
            // 1. 최소 서명자 수 검증 (threshold 이상)
            if signers_list.len() < self.threshold as usize {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("서명자 수({})가 임계치(threshold: {})보다 적습니다.", signers_list.len(), self.threshold),
                ));
            }

            // 2. 최대 서명자 수 검증
            if signers_list.len() > self.num_signers as usize {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("서명자 수({})가 전체 노드 수({})보다 많습니다.", signers_list.len(), self.num_signers),
                ));
            }

            // 3. 중복 식별자 검증 및 범위 검증
            let mut unique_signers = std::collections::BTreeSet::new();
            for &pid in signers_list {
                if pid < 1 || pid > self.num_signers {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("유효하지 않은 서명 참여자 식별자입니다: Party {}", pid),
                    ));
                }
                if !unique_signers.insert(pid) {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("서명 참여자 목록에 중복된 식별자가 있습니다: Party {}", pid),
                    ));
                }
            }

            // 4. 나 자신이 서명 참여자 목록에 포함되어 있는지 검증
            if !unique_signers.contains(&self.party_id) {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!("현재 노드(Party {})가 지정된 서명 참여자 목록({:?})에 포함되어 있지 않습니다.", self.party_id, signers_list),
                ));
            }
            Some(signers_list.clone())
        } else {
            None
        };

        use rand::rngs::OsRng;
        let mut rng = OsRng;

        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

        let msg_vec = message.to_vec();

        self.state = ProtocolState::SigningRound2(SigningRound2State {
            key_package: key_package.clone(),
            message: msg_vec,
            nonces: ZeroizableNonces(nonces),
            commitments: commitments.clone(),
            commitments_map: BTreeMap::new(),
            signers: signers_opt,
        });

        let bytes = bincode::serialize(&commitments)
            .map_err(|e| Error::new(Status::GenericFailure, format!("직렬화 오류: {}", e)))?;
        Ok(bytes)
    }


    pub fn step_internal(&mut self, inputs: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }

        match &mut self.state {
            ProtocolState::DkgRound1(state) => {
                let mut round1_packages = BTreeMap::new();
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];

                    if sender_pid < 1 || sender_pid > self.num_signers {
                        return Err(Error::new(Status::InvalidArg, format!("유효하지 않은 파티 ID: {}", sender_pid)));
                    }
                    if sender_pid == self.party_id {
                        return Err(Error::new(Status::InvalidArg, format!("자신(Party {})의 Round 1 패키지는 입력에 포함할 수 없습니다.", sender_pid)));
                    }
                    let sender_id = Identifier::try_from(sender_pid)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    if round1_packages.contains_key(&sender_id) {
                        return Err(Error::new(Status::InvalidArg, format!("Party {}의 Round 1 패키지가 중복되었습니다.", sender_pid)));
                    }

                    let pkg: frost::keys::dkg::round1::Package = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::GenericFailure, format!("R1 역직렬화 오류: {}", e)))?;
                    round1_packages.insert(sender_id, pkg);
                }

                if round1_packages.len() != (self.num_signers - 1) as usize {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("DKG Round 1 패키지 수가 부족합니다: 기대값 {}, 수신값 {}", self.num_signers - 1, round1_packages.len()),
                    ));
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
                    let target_pid = *self.id_to_pid.get(&receiver_id).unwrap_or(&0);

                    buf.extend_from_slice(&target_pid.to_be_bytes()); // 2 bytes BE
                    buf.extend_from_slice(&bincode::serialize(&pkg).unwrap());
                    outputs.push(buf);
                }
                Ok(outputs)
            },
            ProtocolState::DkgRound2(state) => {
                let mut round2_packages = BTreeMap::new();
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];

                    if sender_pid < 1 || sender_pid > self.num_signers {
                        return Err(Error::new(Status::InvalidArg, format!("유효하지 않은 파티 ID: {}", sender_pid)));
                    }
                    if sender_pid == self.party_id {
                        return Err(Error::new(Status::InvalidArg, format!("자신(Party {})의 Round 2 패키지는 입력에 포함할 수 없습니다.", sender_pid)));
                    }
                    let sender_id = Identifier::try_from(sender_pid)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    if round2_packages.contains_key(&sender_id) {
                        return Err(Error::new(Status::InvalidArg, format!("Party {}의 Round 2 패키지가 중복되었습니다.", sender_pid)));
                    }

                    let pkg: frost::keys::dkg::round2::Package = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::GenericFailure, format!("R2 역직렬화 오류: {}", e)))?;
                    round2_packages.insert(sender_id, pkg);
                }

                if round2_packages.len() != (self.num_signers - 1) as usize {
                    return Err(Error::new(
                        Status::InvalidArg,
                        format!("DKG Round 2 패키지 수가 부족합니다: 기대값 {}, 수신값 {}", self.num_signers - 1, round2_packages.len()),
                    ));
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
                let my_id = Identifier::try_from(self.party_id)
                    .map_err(|e| Error::new(Status::InvalidArg, format!("식별자 생성 오류: {}", e)))?;
                state.commitments_map.insert(my_id, state.commitments.clone());

                let mut collected_pids = vec![self.party_id];

                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];

                    if sender_pid < 1 || sender_pid > self.num_signers {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("유효하지 않은 서명 참여자 식별자입니다: Party {}", sender_pid),
                        ));
                    }

                    // 검증: 지정된 서명 참여자 목록이 있는 경우 속해 있는지 확인
                    if let Some(ref explicit_signers) = state.signers {
                        if !explicit_signers.contains(&sender_pid) {
                            return Err(Error::new(
                                Status::InvalidArg,
                                format!("허용되지 않은 서명 참여자 식별자입니다: Party {} (지정된 서명자: {:?})", sender_pid, explicit_signers),
                            ));
                        }
                    }

                    // 자신(자체 노드)의 Commitment는 이미 등록되어 있으므로 건너뜀
                    if sender_pid == self.party_id {
                        continue;
                    }

                    let sender_id = Identifier::try_from(sender_pid)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("유효하지 않은 식별자(Party {}): {}", sender_pid, e)))?;

                    // 검증: 이미 수집된 식별자인지 확인 (중복 방지)
                    if state.commitments_map.contains_key(&sender_id) {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("Party {}의 Commitment가 이미 수집되었습니다 (중복 식별자 유입).", sender_pid),
                        ));
                    }

                    let comm: frost::round1::SigningCommitments = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("Party {}의 Commitment 역직렬화 오류: {}", sender_pid, e)))?;

                    state.commitments_map.insert(sender_id, comm);
                    collected_pids.push(sender_pid);
                }

                // 검증: 모든 지정 서명자의 Commitment가 수집되었는지 또는 threshold 이상인지 확인
                let final_signers = if let Some(ref explicit_signers) = state.signers {
                    for &expected_pid in explicit_signers {
                        let exp_id = Identifier::try_from(expected_pid)
                            .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                        if !state.commitments_map.contains_key(&exp_id) {
                            return Err(Error::new(
                                Status::InvalidArg,
                                format!("Party {}의 Commitment가 누락되었습니다. (수집 현황: {}/{})", expected_pid, state.commitments_map.len(), explicit_signers.len()),
                            ));
                        }
                    }
                    explicit_signers.clone()
                } else {
                    if state.commitments_map.len() < self.threshold as usize {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("수집된 서명 참여자 수({})가 임계치(threshold: {})보다 적습니다.", state.commitments_map.len(), self.threshold),
                        ));
                    }
                    collected_pids.sort_unstable();
                    collected_pids
                };

                let signing_package = frost::SigningPackage::new(state.commitments_map.clone(), &state.message);

                let signature_share = frost::round2::sign(&signing_package, &state.nonces, &state.key_package)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("서명 조각 생성 오류: {}", e)))?;

                let mut buf = Vec::new();
                let zero_pid: u16 = 0; // Broadcast
                let sig_share_bytes = bincode::serialize(&signature_share).unwrap();
                buf.extend_from_slice(&zero_pid.to_be_bytes());
                buf.extend_from_slice(&sig_share_bytes);

                let mut signature_shares = BTreeMap::new();
                signature_shares.insert(my_id, signature_share);

                let pubkey_pkg = self.pubkey_package.clone()
                    .ok_or_else(|| Error::new(Status::GenericFailure, "공개키 패키지가 없습니다."))?;

                // 여기서 state가 Aggregation으로 바뀌면서 SigningRound2State가 drop되고,
                // state.nonces: ZeroizableNonces의 Drop이 호출되어 Nonce 메모리가 자동으로 제로화됩니다!
                self.state = ProtocolState::Aggregation(AggregationState {
                    signing_package,
                    pubkey_package: pubkey_pkg,
                    signature_shares,
                    signers: final_signers,
                });

                Ok(vec![buf])
            },
            ProtocolState::Aggregation(state) => {
                for input in &inputs {
                    let sender_pid = read_u16(input)?;
                    let payload = &input[2..];

                    // 검증: 지정된 서명 참여자 목록에 속해 있는지 확인
                    if !state.signers.contains(&sender_pid) {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("허용되지 않은 서명 참여자 식별자입니다: Party {} (지정된 서명자: {:?})", sender_pid, state.signers),
                        ));
                    }

                    // 자신(자체 노드)의 서명 조각은 이미 등록되어 있으므로 건너뜀
                    if sender_pid == self.party_id {
                        continue;
                    }

                    let sender_id = Identifier::try_from(sender_pid)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("유효하지 않은 식별자(Party {}): {}", sender_pid, e)))?;


                    // 검증: 이미 수집된 식별자인지 확인 (중복 방지)
                    if state.signature_shares.contains_key(&sender_id) {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("Party {}의 Signature Share가 이미 수집되었습니다 (중복 식별자 유입).", sender_pid),
                        ));
                    }

                    let share: frost::round2::SignatureShare = bincode::deserialize(payload)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("Party {}의 서명 조각(Signature Share) 역직렬화 오류: {}", sender_pid, e)))?;

                    // 서명 조각 개별 검증 (불량 서명 조각 감지)
                    let verifying_share = state.pubkey_package.verifying_shares().get(&sender_id)
                        .ok_or_else(|| Error::new(Status::InvalidArg, format!("Party {}에 대한 VerifyingShare를 찾을 수 없습니다.", sender_pid)))?;
                    let verifying_key = state.pubkey_package.verifying_key();

                    frost_core::verify_signature_share(
                        sender_id,
                        verifying_share,
                        &share,
                        &state.signing_package,
                        verifying_key,
                    ).map_err(|e| Error::new(Status::InvalidArg, format!("불량 서명 조각 감지: Party {}의 서명 조각 검증 실패 ({})", sender_pid, e)))?;


                    state.signature_shares.insert(sender_id, share);
                }

                // 검증: 모든 지정 서명자의 Signature Share가 수집되었는지 확인
                for &expected_pid in &state.signers {
                    let exp_id = Identifier::try_from(expected_pid)
                        .map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
                    if !state.signature_shares.contains_key(&exp_id) {
                        return Err(Error::new(
                            Status::InvalidArg,
                            format!("Party {}의 서명 조각이 누락되었습니다. (수집 현황: {}/{})", expected_pid, state.signature_shares.len(), state.signers.len()),
                        ));
                    }
                }

                let signature = frost::aggregate(&state.signing_package, &state.signature_shares, &state.pubkey_package)
                    .map_err(|e| Error::new(Status::GenericFailure, format!("서명 집약(Aggregation) 오류: {}", e)))?;

                let sig_bytes = signature.serialize()
                    .map_err(|e| Error::new(Status::GenericFailure, format!("최종 서명 직렬화 오류: {}", e)))?;

                self.state = ProtocolState::SigningDone(sig_bytes);
                Ok(Vec::new())
            }
            _ => Err(Error::new(Status::GenericFailure, "현재 상태에서는 step을 수행할 수 없습니다 (Invalid State).")),
        }
    }

    pub fn get_public_key_bytes(&self) -> Result<Vec<u8>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let pkg = self.pubkey_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "공개키 없음"))?;
        Ok(pkg.verifying_key().serialize().unwrap().to_vec())
    }

    pub fn get_signature(&self) -> Result<Vec<u8>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        if let ProtocolState::SigningDone(sig) = &self.state {
            Ok(sig.clone())
        } else {
            Err(Error::new(Status::GenericFailure, "서명 미완료"))
        }
    }

    pub fn export_keyshare(&self) -> Result<Vec<u8>> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let key = self.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 키가 없습니다."))?;
        let pubkey = self.pubkey_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 공개키 패키지가 없습니다."))?;

        let data = (key, pubkey);
        let bytes = bincode::serialize(&data)
            .map_err(|e| Error::new(Status::GenericFailure, format!("키쉐어 직렬화 오류: {}", e)))?;
        Ok(bytes)
    }

    pub fn import_keyshare(&mut self, data: &[u8]) -> Result<()> {
        if self.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let (key, pubkey): (KeyPackage, PublicKeyPackage) = bincode::deserialize(data)
            .map_err(|e| Error::new(Status::GenericFailure, format!("키쉐어 역직렬화 오류: {}", e)))?;

        self.key_package = Some(key.clone());
        self.pubkey_package = Some(pubkey.clone());
        self.state = ProtocolState::DkgDone(key, pubkey);
        Ok(())
    }

}

// Helper to extract u16 from buffer (Big Endian)
fn read_u16(buf: &[u8]) -> Result<u16> {
    if buf.len() < 2 {
        return Err(Error::new(Status::InvalidArg, "입력 버퍼의 길이가 너무 짧습니다 (최소 2바이트 필요)"));
    }
    let arr: [u8; 2] = buf[0..2].try_into().map_err(|_| Error::new(Status::GenericFailure, "파티 ID 변환 오류"))?;
    Ok(u16::from_be_bytes(arr))
}

pub struct StepTask {
    inner: Arc<Mutex<FrostExecutorInner>>,
    inputs: Vec<Vec<u8>>,
}

impl Task for StepTask {
    type Output = Vec<Vec<u8>>;
    type JsValue = Vec<Buffer>;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if inner.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        inner.step_internal(std::mem::take(&mut self.inputs))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into_iter().map(Buffer::from).collect())
    }
}

#[napi]
pub struct FrostExecutor {
    inner: Arc<Mutex<FrostExecutorInner>>,
}

impl Drop for FrostExecutor {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            if !inner.is_destroyed {
                inner.destroy_internal();
            }
        }
    }
}

#[napi]
impl FrostExecutor {
    #[napi(constructor)]
    pub fn new(party_id: u16, num_signers: u16, threshold: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FrostExecutorInner::new(party_id, num_signers, threshold))),
        }
    }

    #[napi]
    pub fn is_destroyed(&self) -> Result<bool> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        Ok(inner.is_destroyed)
    }

    #[napi(js_name = "is_destroyed")]
    pub fn is_destroyed_alias(&self) -> Result<bool> {
        self.is_destroyed()
    }

    #[napi]
    pub fn destroy(&self) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if !inner.is_destroyed {
            inner.destroy_internal();
        }
        Ok(())
    }

    #[napi]
    pub fn start_keygen(&self) -> Result<Buffer> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let res = inner.start_keygen()?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub fn start_signing(&self, message: Buffer, signers: Option<Vec<u16>>) -> Result<Buffer> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let res = inner.start_signing(message.as_ref(), signers)?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub fn step(&self, inputs: Vec<Buffer>) -> Result<Vec<Buffer>> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let raw_inputs: Vec<Vec<u8>> = inputs.iter().map(|b| b.to_vec()).collect();
        let raw_outputs = inner.step_internal(raw_inputs)?;
        Ok(raw_outputs.into_iter().map(Buffer::from).collect())
    }

    #[napi]
    pub fn step_async(&self, inputs: Vec<Buffer>) -> Result<AsyncTask<StepTask>> {
        let raw_inputs: Vec<Vec<u8>> = inputs.iter().map(|b| b.to_vec()).collect();
        Ok(AsyncTask::new(StepTask {
            inner: self.inner.clone(),
            inputs: raw_inputs,
        }))
    }

    #[napi(js_name = "step_async")]
    pub fn step_async_alias(&self, inputs: Vec<Buffer>) -> Result<AsyncTask<StepTask>> {
        self.step_async(inputs)
    }

    #[napi]
    pub fn get_public_key_bytes(&self) -> Result<Buffer> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let res = inner.get_public_key_bytes()?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub fn get_signature(&self) -> Result<Buffer> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let res = inner.get_signature()?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub fn export_keyshare(&self) -> Result<Buffer> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        let res = inner.export_keyshare()?;
        Ok(Buffer::from(res))
    }

    #[napi]
    pub fn import_keyshare(&self, data: Buffer) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        inner.import_keyshare(data.as_ref())
    }


    #[napi]
    pub fn export_keyshare_handle(&self) -> Result<External<FrostKeyShareHandle>> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if inner.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let key = inner.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 키가 없습니다."))?;
        let pubkey = inner.pubkey_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 공개키 패키지가 없습니다."))?;
        Ok(External::new(FrostKeyShareHandle {
            key_package: key.clone(),
            pubkey_package: pubkey.clone(),
        }))
    }

    #[napi]
    pub fn import_keyshare_handle(&self, handle: External<FrostKeyShareHandle>) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if inner.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        inner.key_package = Some(handle.key_package.clone());
        inner.pubkey_package = Some(handle.pubkey_package.clone());
        inner.state = ProtocolState::DkgDone(handle.key_package.clone(), handle.pubkey_package.clone());
        Ok(())
    }

    #[napi]
    pub fn export_key_package_handle(&self) -> Result<External<KeyPackage>> {
        let inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if inner.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let key = inner.key_package.as_ref()
            .ok_or_else(|| Error::new(Status::InvalidArg, "내보낼 키가 없습니다."))?;
        Ok(External::new(key.clone()))
    }

    #[napi]
    pub fn import_key_package_handle(
        &self,
        handle: External<KeyPackage>,
        pubkey_package_bin: Option<Buffer>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| Error::from_reason("Executor mutex poisoned"))?;
        if inner.is_destroyed {
            return Err(Error::from_reason("Executor has already been destroyed"));
        }
        let key = (*handle).clone();
        let pubkey = if let Some(buf) = pubkey_package_bin {
            bincode::deserialize(&buf)
                .map_err(|e| Error::new(Status::GenericFailure, format!("공개키 역직렬화 오류: {}", e)))?
        } else if let Some(ref existing) = inner.pubkey_package {
            existing.clone()
        } else {
            return Err(Error::new(Status::InvalidArg, "공개키 패키지가 필요합니다."));
        };
        inner.key_package = Some(key.clone());
        inner.pubkey_package = Some(pubkey.clone());
        inner.state = ProtocolState::DkgDone(key, pubkey);
        Ok(())
    }

    #[napi]
    pub fn get_identifier_bytes(party_id: u16) -> Result<Buffer> {
        let identifier = Identifier::try_from(party_id).map_err(|e| Error::new(Status::InvalidArg, format!("{}", e)))?;
        Ok(Buffer::from(bincode::serialize(&identifier).unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_directed_raw(sender_pid: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + payload.len());
        buf.extend_from_slice(&sender_pid.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn test_nonce_zeroization_on_drop_and_destroy() {
        let mut rng = OsRng;
        let (shares, _pubkeys) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rng,
        ).unwrap();
        let secret = shares.values().next().unwrap();

        let (nonces, _commitments) = frost::round1::commit(secret.signing_share(), &mut rng);
        let mut z_nonces = ZeroizableNonces(nonces);

        let bytes_before = bincode::serialize(&z_nonces.0).unwrap();
        assert!(bytes_before.iter().any(|&b| b != 0));

        z_nonces.zeroize();
        let bytes_after = bincode::serialize(&z_nonces.0).unwrap();
        assert_ne!(bytes_before, bytes_after);

        let mut inner = FrostExecutorInner::new(1, 3, 2);
        assert!(!inner.is_destroyed);

        inner.destroy_internal();
        assert!(inner.is_destroyed);

        // Idempotent destroy
        inner.destroy_internal();
        assert!(inner.is_destroyed);

        // Calls after destroy fail
        assert!(inner.step_internal(vec![]).is_err());
        assert!(inner.start_keygen().is_err());
        assert!(inner.start_signing(b"test", None).is_err());
    }


    #[test]
    fn test_frost_full_protocol_2round_signing_and_aggregation() {
        let n = 3u16;
        let t = 2u16;
        let party_ids = vec![1u16, 2u16, 3u16];

        let mut inners: Vec<FrostExecutorInner> = party_ids.iter().map(|&pid| FrostExecutorInner::new(pid, n, t)).collect();

        // DKG Round 1
        let mut r1_payloads = Vec::new();
        for (i, &pid) in party_ids.iter().enumerate() {
            let pkg = inners[i].start_keygen().unwrap();
            r1_payloads.push((pid, pkg.to_vec()));
        }

        // DKG Round 2
        let mut r2_directed = Vec::new();
        for (i, &my_pid) in party_ids.iter().enumerate() {
            let inputs: Vec<Vec<u8>> = r1_payloads.iter()
                .filter(|(pid, _)| *pid != my_pid)
                .map(|(pid, payload)| make_directed_raw(*pid, payload))
                .collect();

            let outputs = inners[i].step_internal(inputs).unwrap();
            for out in outputs {
                r2_directed.push((my_pid, out));
            }
        }

        // DKG Finalize
        for (i, &my_pid) in party_ids.iter().enumerate() {
            let mut my_inputs = Vec::new();
            for (sender_pid, full_buf) in &r2_directed {
                let target_pid = u16::from_be_bytes(full_buf[0..2].try_into().unwrap());
                let pkg_bytes = &full_buf[2..];
                if target_pid == my_pid {
                    my_inputs.push(make_directed_raw(*sender_pid, pkg_bytes));
                }
            }
            inners[i].step_internal(my_inputs).unwrap();
        }

        let pub_key_0 = inners[0].get_public_key_bytes().unwrap();
        for inner in &inners {
            let pk = inner.get_public_key_bytes().unwrap();
            assert_eq!(&pk, &pub_key_0);
        }


        // Signing Round 1 (Commitments) with signers [1, 2]
        let message = b"Rust integration test FROST Ed25519 Phase 2";
        let signers = vec![1u16, 2u16];

        let mut commitments = Vec::new();
        for &pid in &signers {
            let idx = (pid - 1) as usize;
            let comm = inners[idx].start_signing(message, Some(signers.clone())).unwrap();
            commitments.push((pid, comm.to_vec()));
        }

        // Signing Round 2 (Signature shares)
        let mut sig_shares = Vec::new();
        for &my_pid in &signers {
            let idx = (my_pid - 1) as usize;
            let inputs: Vec<Vec<u8>> = commitments.iter()
                .filter(|(pid, _)| *pid != my_pid)
                .map(|(pid, comm)| make_directed_raw(*pid, comm))
                .collect();

            let outputs = inners[idx].step_internal(inputs).unwrap();
            assert_eq!(outputs.len(), 1);
            let share_payload = outputs[0][2..].to_vec();
            sig_shares.push((my_pid, share_payload));
        }

        // Aggregation
        for &my_pid in &signers {
            let idx = (my_pid - 1) as usize;
            let inputs: Vec<Vec<u8>> = sig_shares.iter()
                .map(|(pid, share)| make_directed_raw(*pid, share))
                .collect();

            inners[idx].step_internal(inputs).unwrap();
            let sig = inners[idx].get_signature().unwrap();
            assert_eq!(sig.len(), 64);

            let verifying_key = frost::VerifyingKey::deserialize(pub_key_0.as_slice().try_into().unwrap()).unwrap();
            let signature = frost::Signature::deserialize(sig.as_slice().try_into().unwrap()).unwrap();
            verifying_key.verify(message, &signature).expect("Signature verification failed!");

            // Destroy
            inners[idx].destroy_internal();
            assert!(inners[idx].is_destroyed);
            assert!(inners[idx].step_internal(vec![]).is_err());
        }

    }

    #[test]
    fn test_invalid_signer_identifier_and_bad_share_rejection() {
        let n = 3u16;
        let t = 2u16;
        let party_ids = vec![1u16, 2u16, 3u16];

        let mut inners: Vec<FrostExecutorInner> = party_ids.iter().map(|&pid| FrostExecutorInner::new(pid, n, t)).collect();

        // DKG
        let mut r1_payloads = Vec::new();
        for (i, &pid) in party_ids.iter().enumerate() {
            r1_payloads.push((pid, inners[i].start_keygen().unwrap().to_vec()));
        }
        let mut r2_directed = Vec::new();
        for (i, &my_pid) in party_ids.iter().enumerate() {
            let inputs: Vec<Vec<u8>> = r1_payloads.iter()
                .filter(|(pid, _)| *pid != my_pid)
                .map(|(pid, payload)| make_directed_raw(*pid, payload))
                .collect();
            for out in inners[i].step_internal(inputs).unwrap() {
                r2_directed.push((my_pid, out));
            }
        }
        for (i, &my_pid) in party_ids.iter().enumerate() {
            let mut my_inputs = Vec::new();
            for (sender_pid, full_buf) in &r2_directed {
                let target_pid = u16::from_be_bytes(full_buf[0..2].try_into().unwrap());
                if target_pid == my_pid {
                    my_inputs.push(make_directed_raw(*sender_pid, &full_buf[2..]));
                }
            }
            inners[i].step_internal(my_inputs).unwrap();
        }

        // Start signing with signers [1, 2]
        let message = b"test invalid identifier message";
        let signers = vec![1u16, 2u16];

        let comm1 = inners[0].start_signing(message, Some(signers.clone())).unwrap().to_vec();
        let comm2 = inners[1].start_signing(message, Some(signers.clone())).unwrap().to_vec();


        // 1. Party 3 unauthorized in Round 1
        let rogue_input = make_directed_raw(3, &comm2);
        let err = inners[0].step_internal(vec![rogue_input]).unwrap_err();
        assert!(err.reason.contains("허용되지 않은 서명 참여자 식별자"));

        // 2. Duplicate commitment from Party 2
        let dup_input = vec![
            make_directed_raw(2, &comm2),
            make_directed_raw(2, &comm2),
        ];
        let err_dup = inners[0].step_internal(dup_input).unwrap_err();
        assert!(err_dup.reason.contains("중복 식별자 유입"));

        // Valid Round 1 (Party 2 commitment was already added during dup_input's first item, now complete step for Party 1)
        let out1 = inners[0].step_internal(vec![]).unwrap();
        let out2 = inners[1].step_internal(vec![make_directed_raw(1, &comm1)]).unwrap();

        let share1 = &out1[0][2..];
        let _share2 = &out2[0][2..];

        // 3. Corrupted / fraudulent signature share in Round 2
        let (bogus_nonces, bogus_comm1) = frost::round1::commit(inners[0].key_package.as_ref().unwrap().signing_share(), &mut OsRng);
        let (_, bogus_comm2) = frost::round1::commit(inners[1].key_package.as_ref().unwrap().signing_share(), &mut OsRng);
        let dummy_pkg = frost::SigningPackage::new(
            BTreeMap::from([
                (Identifier::try_from(1).unwrap(), bogus_comm1),
                (Identifier::try_from(2).unwrap(), bogus_comm2),
            ]),
            b"completely wrong message"
        );
        let bad_share = frost::round2::sign(&dummy_pkg, &bogus_nonces, inners[0].key_package.as_ref().unwrap()).unwrap();
        let bad_share1 = bincode::serialize(&bad_share).unwrap();


        let err_bad_share = inners[1].step_internal(vec![make_directed_raw(1, &bad_share1)]).unwrap_err();
        assert!(err_bad_share.reason.contains("불량 서명 조각 감지"));


        // 4. Unauthorized signer in Round 2 (Party 3)
        let err_rogue_share = inners[1].step_internal(vec![make_directed_raw(3, share1)]).unwrap_err();
        assert!(err_rogue_share.reason.contains("허용되지 않은 서명 참여자 식별자"));

        // 5. Duplicate signature share in Round 2
        let dup_share_input = vec![
            make_directed_raw(1, share1),
            make_directed_raw(1, share1),
        ];
        let err_dup_share = inners[1].step_internal(dup_share_input).unwrap_err();
        assert!(err_dup_share.reason.contains("중복 식별자 유입"));

    }

    #[test]
    fn test_step_task_worker() {
        let n = 3u16;
        let t = 2u16;
        let inner = Arc::new(Mutex::new(FrostExecutorInner::new(1, n, t)));

        // Call start_keygen
        let out = {
            let mut guard = inner.lock().unwrap();
            guard.start_keygen().unwrap()
        };
        assert!(!out.is_empty());

        // Test StepTask compute with empty inputs (should error because other parties' packages are missing)
        let mut task = StepTask {
            inner: inner.clone(),
            inputs: vec![],
        };
        let err = task.compute().unwrap_err();
        assert!(err.reason.contains("DKG Round 1 패키지 수가 부족합니다"));

        // Destroy inner and test StepTask compute
        {
            let mut guard = inner.lock().unwrap();
            guard.destroy_internal();
        }
        let mut task2 = StepTask {
            inner: inner.clone(),
            inputs: vec![],
        };
        let err2 = task2.compute().unwrap_err();
        assert!(err2.reason.contains("Executor has already been destroyed"));
    }
}