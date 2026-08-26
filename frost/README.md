# @kshan0515/frost-node-binding

Node.js native binding for FROST (Flexible Round-Optimized Schnorr Threshold Signatures) on Ed25519 curve.

## 개요 (Overview)

`@kshan0515/frost-node-binding`은 Zcash Foundation의 [frost-core](https://github.com/ZcashFoundation/frost) 및 `frost-ed25519` 라이브러리를 기반으로 구현된 고성능 N-API(napi-rs) Node.js 네이티브 바인딩 모듈입니다.

- **지원 곡선**: Ed25519 (EdDSA)
- **주요 기능**:
  - 분산 키 생성 (DKG: Distributed Key Generation) - 3 Round
  - 임계치 서명 (Threshold Signing) - 2 Round + Aggregation
  - 세션 기반 실행기 (`FrostExecutor`) 제공
  - 무상태(Stateless) API (`FrostDkgState`, `FrostSigningState`) 제공
  - SoftHSM 및 Key-Registry 연동을 위한 KeyShare 직렬화/역직렬화 지원

## 설치 (Installation)

```bash
npm install @kshan0515/frost-node-binding
# 또는
pnpm add @kshan0515/frost-node-binding
```

## 사용법 (Usage)

### FrostExecutor (Stateful Session Runner) 예시

```typescript
import { FrostExecutor } from '@kshan0515/frost-node-binding';

const n = 3; // 전체 참여자 수
const t = 2; // 임계치 (Threshold)
const partyId = 1; // 1-based Party ID

// 1. DKG 세션 초기화
const executor = new FrostExecutor(partyId, n, t);

// 2. Round 1 시작 (Broadcast 패키지 생성)
const r1Package = executor.startKeygen();

// 3. Round 2 진행 (다른 노드들의 R1 패키지 수신 후 step 실행)
// inputs 포맷: [Sender PID(2바이트 BE) + Payload]
const r2DirectedOutputs = executor.step(r1Inputs);

// 4. DKG 완료 (다른 노드들의 R2 Direct 패키지 수신 후 step 실행)
executor.step(r2Inputs);

// 그룹 공개키 조회
const pubKeyBytes = executor.getPublicKeyBytes();
console.log('그룹 Ed25519 공개키:', Buffer.from(pubKeyBytes).toString('hex'));

// 5. 서명 세션 시작
const message = Buffer.from('Hello FROST');
const signers = [1, 2]; // 서명 참여 노드 목록
const commitPayload = executor.startSigning(message, signers);

// 6. 서명 Round 2 및 집약(Aggregation)
const sigShareOutput = executor.step(commitmentInputs);
executor.step(signatureShareInputs);

// 최종 Ed25519 서명 조회 (64 바이트)
const signature = executor.getSignature();
console.log('최종 서명:', Buffer.from(signature).toString('hex'));
```

## 개발 및 빌드 (Development & Build)

### 요구 사항
- Rust 1.81 이상
- Node.js 18 이상
- pnpm

### 빌드 및 테스트
```bash
# 디버그 빌드
pnpm run build:debug

# 릴리즈 빌드
pnpm run build

# 단위 테스트 실행
pnpm test
```

## 라이선스 (License)

MIT License
