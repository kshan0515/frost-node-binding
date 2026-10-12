import { FrostExecutor, FrostDkgState, FrostSigningState } from '../index';
const { webcrypto } = require('node:crypto');

describe('FROST Phase 2 기능 검증 테스트 Suite', () => {
  const t = 2;
  const n = 3;
  const partyIds = [1, 2, 3];

  describe('1. 비동기 워커화 (stepAsync / step_async) 파이프라인 검증', () => {
    it('stepAsync 기반 DKG 및 2라운드 서명 Aggregation 전 과정 비동기 완료 및 WebCrypto 검증', async () => {
      const executors = partyIds.map(pid => new FrostExecutor(pid, n, t));

      // 1. DKG Round 1
      const round1Payloads: { pid: number; payload: Buffer }[] = [];
      for (let i = 0; i < n; i++) {
        const pkg = executors[i].startKeygen();
        round1Payloads.push({ pid: partyIds[i], payload: Buffer.from(pkg) });
      }

      // 2. DKG Round 2 (비동기 stepAsync 호출)
      const round2DirectedMessages: { senderPid: number; payload: Buffer }[] = [];
      for (let i = 0; i < n; i++) {
        const exec = executors[i];
        const myPid = partyIds[i];

        const inputs = round1Payloads
          .filter(p => p.pid !== myPid)
          .map(p => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(p.pid, 0);
            return Buffer.concat([pidBuf, p.payload]);
          });

        const outputs = await exec.stepAsync(inputs);
        outputs.forEach(buf => {
          round2DirectedMessages.push({ senderPid: myPid, payload: Buffer.from(buf) });
        });
      }

      // 3. DKG Finalize (비동기 step_async alias 호출)
      for (let i = 0; i < n; i++) {
        const myPid = partyIds[i];
        const exec = executors[i];

        const myInputs: Buffer[] = [];
        round2DirectedMessages.forEach(msg => {
          const fullBuf = msg.payload;
          const targetPid = fullBuf.readUInt16BE(0);
          const packageBytes = fullBuf.subarray(2);

          if (targetPid === myPid) {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(msg.senderPid, 0);
            myInputs.push(Buffer.concat([pidBuf, packageBytes]));
          }
        });

        await exec.step_async(myInputs);
      }

      // 공개키 일치 검증
      const pubKeys = executors.map(e => e.getPublicKeyBytes());
      const firstKeyHex = Buffer.from(pubKeys[0]).toString('hex');
      pubKeys.forEach(k => {
        expect(Buffer.from(k).toString('hex')).toBe(firstKeyHex);
      });

      // 4. 서명 시작 (signers 지정: [1, 2])
      const message = Buffer.from('FROST Phase 2 Async Step Verification');
      const signers = [1, 2];
      const activeExecutors = [executors[0], executors[1]];
      const activePids = [1, 2];

      const commitmentsPayloads: { pid: number; payload: Buffer }[] = [];
      for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const pid = activePids[i];
        const comm = exec.startSigning(message, signers);
        commitmentsPayloads.push({ pid, payload: Buffer.from(comm) });
      }

      // 5. 서명 Round 2 (stepAsync)
      const signatureSharesPayloads: { pid: number; payload: Buffer }[] = [];
      for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const myPid = activePids[i];

        const inputs = commitmentsPayloads
          .filter(c => c.pid !== myPid)
          .map(c => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(c.pid, 0);
            return Buffer.concat([pidBuf, c.payload]);
          });

        const output = await exec.stepAsync(inputs);
        const sharePayload = Buffer.from(output[0]).subarray(2);
        signatureSharesPayloads.push({ pid: myPid, payload: sharePayload });
      }

      // 6. Aggregation (stepAsync)
      let finalSignature: Buffer | null = null;
      for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const inputs = signatureSharesPayloads.map(s => {
          const pidBuf = Buffer.alloc(2);
          pidBuf.writeUInt16BE(s.pid, 0);
          return Buffer.concat([pidBuf, s.payload]);
        });

        await exec.stepAsync(inputs);
        finalSignature = Buffer.from(exec.getSignature());
      }

      expect(finalSignature).not.toBeNull();
      expect(finalSignature!.length).toBe(64);

      // 7. WebCrypto Ed25519 서명 검증
      const subtle = webcrypto.subtle;
      const key = await subtle.importKey(
        'raw',
        new Uint8Array(pubKeys[0]),
        { name: 'Ed25519' },
        true,
        ['verify']
      );

      const isValid = await subtle.verify(
        { name: 'Ed25519' },
        key,
        new Uint8Array(finalSignature!),
        new Uint8Array(message)
      );

      expect(isValid).toBe(true);
    });
  });

  describe('2. 명시적 destroy 및 Use-After-Free 방어 검증', () => {
    it('destroy() 호출 후 isDestroyed() 상태 및 이후 호출 시 에러 throw 검증', async () => {
      const executor = new FrostExecutor(1, n, t);
      expect(executor.isDestroyed()).toBe(false);
      expect(executor.is_destroyed()).toBe(false);

      executor.startKeygen();

      // 명시적 파기
      executor.destroy();
      expect(executor.isDestroyed()).toBe(true);
      expect(executor.is_destroyed()).toBe(true);

      // 이미 파기된 객체에 대한 동기 step 호출 시 에러 검증
      expect(() => {
        executor.step([]);
      }).toThrow(/Executor has already been destroyed/);

      // 비동기 stepAsync 호출 시 거부(reject) 검증
      await expect(executor.stepAsync([])).rejects.toThrow(/Executor has already been destroyed/);

      // 기타 메서드 호출 시에도 차단 검증
      expect(() => {
        executor.startKeygen();
      }).toThrow(/Executor has already been destroyed/);

      expect(() => {
        executor.startSigning(Buffer.from('test'));
      }).toThrow(/Executor has already been destroyed/);

      expect(() => {
        executor.exportKeyshare();
      }).toThrow(/Executor has already been destroyed/);
    });
  });

  describe('3. V8 힙 격리를 위한 External 핸들 인터페이스 검증', () => {
    it('FrostExecutor exportKeyshareHandle / importKeyshareHandle 기반 키 로드 및 서명', async () => {
      // 1. DKG를 완료한 후 키쉐어 핸들 내보내기
      const exec1 = new FrostExecutor(1, n, t);
      const exec2 = new FrostExecutor(2, n, t);
      const exec3 = new FrostExecutor(3, n, t);
      const all = [exec1, exec2, exec3];

      const r1 = all.map((e, idx) => ({ pid: idx + 1, payload: e.startKeygen() }));
      const r2msgs: { senderPid: number; payload: Buffer }[] = [];

      for (let i = 0; i < n; i++) {
        const myPid = i + 1;
        const inputs = r1
          .filter(p => p.pid !== myPid)
          .map(p => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(p.pid, 0);
            return Buffer.concat([pidBuf, p.payload]);
          });
        const outs = all[i].step(inputs);
        outs.forEach(b => r2msgs.push({ senderPid: myPid, payload: Buffer.from(b) }));
      }

      for (let i = 0; i < n; i++) {
        const myPid = i + 1;
        const myInputs: Buffer[] = [];
        r2msgs.forEach(msg => {
          const targetPid = msg.payload.readUInt16BE(0);
          if (targetPid === myPid) {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(msg.senderPid, 0);
            myInputs.push(Buffer.concat([pidBuf, msg.payload.subarray(2)]));
          }
        });
        all[i].step(myInputs);
      }

      // V8 힙 격리 핸들 추출
      const handle1 = exec1.exportKeyshareHandle();
      const handle2 = exec2.exportKeyshareHandle();
      expect(handle1).toBeDefined();

      // 새로운 Executor 인스턴스에 핸들로 키 복원
      const restored1 = new FrostExecutor(1, n, t);
      const restored2 = new FrostExecutor(2, n, t);
      restored1.importKeyshareHandle(handle1);
      restored2.importKeyshareHandle(handle2);

      expect(restored1.getPublicKeyBytes().toString('hex')).toBe(exec1.getPublicKeyBytes().toString('hex'));

      // 복원된 Executor로 서명 수행
      const message = Buffer.from('Testing External handle restoration');
      const signers = [1, 2];
      const comm1 = restored1.startSigning(message, signers);
      const comm2 = restored2.startSigning(message, signers);

      const p1In = [Buffer.concat([Buffer.from([0, 2]), comm2])];
      const p2In = [Buffer.concat([Buffer.from([0, 1]), comm1])];

      const out1 = restored1.step(p1In);
      const out2 = restored2.step(p2In);

      const s1 = out1[0].subarray(2);
      const s2 = out2[0].subarray(2);

      const aggIn = [
        Buffer.concat([Buffer.from([0, 1]), s1]),
        Buffer.concat([Buffer.from([0, 2]), s2]),
      ];

      restored1.step(aggIn);
      const finalSig = restored1.getSignature();
      expect(finalSig.length).toBe(64);

      // WebCrypto 검증
      const key = await webcrypto.subtle.importKey(
        'raw',
        new Uint8Array(restored1.getPublicKeyBytes()),
        { name: 'Ed25519' },
        true,
        ['verify']
      );
      const isValid = await webcrypto.subtle.verify(
        { name: 'Ed25519' },
        key,
        new Uint8Array(finalSig),
        new Uint8Array(message)
      );
      expect(isValid).toBe(true);
    });

    it('FrostDkgState 및 FrostSigningState의 Handle 기반 API 동작 검증', () => {
      // 1. DKG Part 1 Handle
      const dkg1 = FrostDkgState.dkgPart1Handle(1, 2, 2);
      const dkg2 = FrostDkgState.dkgPart1Handle(2, 2, 2);

      // 2. DKG Part 2 Handle
      const id1 = FrostDkgState.getIdentifier(1);
      const id2 = FrostDkgState.getIdentifier(2);

      const r2_1 = FrostDkgState.dkgPart2Handle(dkg1.secretPackage, {
        [id2]: dkg2.round1Package,
      });
      const r2_2 = FrostDkgState.dkgPart2Handle(dkg2.secretPackage, {
        [id1]: dkg1.round1Package,
      });

      // 3. DKG Part 3 Handle (KeyPackage Handle 반환)
      const final1 = FrostDkgState.dkgPart3Handle(
        r2_1.secretPackage,
        { [id2]: dkg2.round1Package },
        { [id2]: r2_2.round2Packages[id1] }
      );
      const final2 = FrostDkgState.dkgPart3Handle(
        r2_2.secretPackage,
        { [id1]: dkg1.round1Package },
        { [id1]: r2_1.round2Packages[id2] }
      );

      // 4. Signing Part 1 Handle
      const s1 = FrostSigningState.signPart1Handle(final1.keyPackage);
      const s2 = FrostSigningState.signPart1Handle(final2.keyPackage);

      // Signing Package 생성
      const message = Buffer.from('DKG handle flow');
      const signingPackage = FrostSigningState.createSigningPackage(message, {
        [id1]: s1.commitments,
        [id2]: s2.commitments,
      });

      // 5. Signing Part 2 Handle
      const share1 = FrostSigningState.signPart2Handle(signingPackage, s1.nonces, final1.keyPackage);
      const share2 = FrostSigningState.signPart2Handle(signingPackage, s2.nonces, final2.keyPackage);

      // 6. Aggregate
      const finalSig = FrostSigningState.aggregate(
        signingPackage,
        {
          [id1]: share1,
          [id2]: share2,
        },
        final1.pubkeyPackage
      );

      expect(finalSig.length).toBe(64);
    });
  });

  describe('4. 서명 참여자 검증 및 식별자 에러 처리 정밀화', () => {
    let readyExecutors: FrostExecutor[];

    beforeEach(() => {
      readyExecutors = partyIds.map(pid => new FrostExecutor(pid, n, t));
      const r1 = readyExecutors.map((e, idx) => ({ pid: idx + 1, payload: e.startKeygen() }));
      const r2msgs: { senderPid: number; payload: Buffer }[] = [];

      for (let i = 0; i < n; i++) {
        const myPid = i + 1;
        const inputs = r1
          .filter(p => p.pid !== myPid)
          .map(p => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(p.pid, 0);
            return Buffer.concat([pidBuf, p.payload]);
          });
        const outs = readyExecutors[i].step(inputs);
        outs.forEach(b => r2msgs.push({ senderPid: myPid, payload: Buffer.from(b) }));
      }

      for (let i = 0; i < n; i++) {
        const myPid = i + 1;
        const myInputs: Buffer[] = [];
        r2msgs.forEach(msg => {
          const targetPid = msg.payload.readUInt16BE(0);
          if (targetPid === myPid) {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(msg.senderPid, 0);
            myInputs.push(Buffer.concat([pidBuf, msg.payload.subarray(2)]));
          }
        });
        readyExecutors[i].step(myInputs);
      }
    });

    it('startSigning 시 서명자 수가 임계치(threshold)보다 적을 때 에러 발생', () => {
      const message = Buffer.from('test');
      expect(() => {
        readyExecutors[0].startSigning(message, [1]); // t=2 인데 1명만 전달
      }).toThrow(/임계치\(threshold: 2\)보다 적습니다/);
    });

    it('startSigning 시 나 자신이 참여자 목록에 없을 때 에러 발생', () => {
      const message = Buffer.from('test');
      expect(() => {
        readyExecutors[0].startSigning(message, [2, 3]); // Party 1이 호출하는데 [2, 3] 지정
      }).toThrow(/현재 노드\(Party 1\)가 지정된 서명 참여자 목록/);
    });

    it('startSigning 시 서명자 목록에 중복 식별자가 포함되었을 때 에러 발생', () => {
      const message = Buffer.from('test');
      expect(() => {
        readyExecutors[0].startSigning(message, [1, 2, 2]);
      }).toThrow(/중복된 식별자가 있습니다/);
    });

    it('Round 1에서 지정된 서명자 외의 비인가 식별자 유입 시 에러 발생', () => {
      const message = Buffer.from('test unauthorized signer');
      const signers = [1, 2];
      readyExecutors[0].startSigning(message, signers);
      const comm2 = readyExecutors[1].startSigning(message, signers);

      // Party 3이 보낸 것처럼 위조한 입력 (signers에 Party 3 없음)
      const fakeInput = Buffer.concat([Buffer.from([0, 3]), comm2]);

      expect(() => {
        readyExecutors[0].step([fakeInput]);
      }).toThrow(/허용되지 않은 서명 참여자 식별자입니다: Party 3/);
    });

    it('Round 1에서 동일 식별자의 중복 Commitment 유입 시 에러 발생', () => {
      const message = Buffer.from('test duplicate commitment');
      const signers = [1, 2];
      readyExecutors[0].startSigning(message, signers);
      const comm2 = readyExecutors[1].startSigning(message, signers);

      const p2Input = Buffer.concat([Buffer.from([0, 2]), comm2]);

      expect(() => {
        readyExecutors[0].step([p2Input, p2Input]);
      }).toThrow(/중복 식별자 유입/);
    });

    it('Round 2에서 불량 서명 조각(Bogus Signature Share) 감지 시 즉시 거부', () => {
      const message = Buffer.from('test bad share rejection');
      const signers = [1, 2];
      const comm1 = readyExecutors[0].startSigning(message, signers);
      const comm2 = readyExecutors[1].startSigning(message, signers);

      // 정상적인 Round 2 서명 조각 생성
      const p1Round2In = [Buffer.concat([Buffer.from([0, 2]), comm2])];
      const p2Round2In = [Buffer.concat([Buffer.from([0, 1]), comm1])];

      readyExecutors[0].step(p1Round2In);
      const out2 = readyExecutors[1].step(p2Round2In);

      const legitShare2 = out2[0].subarray(2);

      // 다른 메시지로 서명된 조각을 주입하여 변조 서명 조각 시뮬레이션
      const otherExec = new FrostExecutor(2, n, t);
      otherExec.importKeyshare(readyExecutors[1].exportKeyshare());
      const otherComm = otherExec.startSigning(Buffer.from('completely different message'), signers);
      const fakeRound2In = [Buffer.concat([Buffer.from([0, 1]), comm1])];
      const badOut = otherExec.step(fakeRound2In);
      const badShare2 = badOut[0].subarray(2);

      // Party 1에게 변조된 badShare2 전달
      const badInput = [Buffer.concat([Buffer.from([0, 2]), badShare2])];

      expect(() => {
        readyExecutors[0].step(badInput);
      }).toThrow(/불량 서명 조각 감지: Party 2의 서명 조각/);
    });

    it('Round 2에서 중복 Signature Share 유입 시 에러 발생', () => {
      const message = Buffer.from('test duplicate share');
      const signers = [1, 2];
      const comm1 = readyExecutors[0].startSigning(message, signers);
      const comm2 = readyExecutors[1].startSigning(message, signers);

      const p1Round2In = [Buffer.concat([Buffer.from([0, 2]), comm2])];
      const p2Round2In = [Buffer.concat([Buffer.from([0, 1]), comm1])];

      readyExecutors[0].step(p1Round2In);
      const out2 = readyExecutors[1].step(p2Round2In);
      const share2 = out2[0].subarray(2);

      const dupShareInput = [
        Buffer.concat([Buffer.from([0, 2]), share2]),
        Buffer.concat([Buffer.from([0, 2]), share2]),
      ];

      expect(() => {
        readyExecutors[0].step(dupShareInput);
      }).toThrow(/중복 식별자 유입/);
    });
  });
});
