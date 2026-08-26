import { FrostExecutor } from '../index';
const { webcrypto } = require('node:crypto');

describe('FROST Executor 통합 테스트', () => {
  const t = 2; 
  const n = 3; 
  const partyIds = [1, 2, 3];

  it('FrostExecutor를 통한 DKG 및 서명 절차 검증', async () => {
    // 1. 초기화
    const executors = partyIds.map(pid => new FrostExecutor(pid, n, t));

    // 2. DKG 시작 (Round 1)
    console.log('--- DKG 시작 ---');
    const round1Payloads: { pid: number, payload: Buffer }[] = [];
    
    for (let i = 0; i < n; i++) {
      const pkg = executors[i].startKeygen();
      round1Payloads.push({ pid: partyIds[i], payload: Buffer.from(pkg) });
    }

    // 3. DKG Round 2 진행
    console.log('--- DKG Round 2 ---');
    
    const round2DirectedMessages: { senderPid: number, payload: Buffer }[] = [];

    for (let i = 0; i < n; i++) {
      const exec = executors[i];
      const myPid = partyIds[i];
      
      // 나를 제외한 다른 사람들의 패키지 전달
      // frost-ed25519 part2 requires N-1 round1 packages
      const inputs = round1Payloads
        .filter(p => p.pid !== myPid)
        .map(p => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(p.pid, 0);
            return Buffer.concat([pidBuf, p.payload]);
      });
      
      console.log(`Party ${myPid} step inputs length: ${inputs.length}`);
      const outputs = exec.step(inputs); 
      
      // 출력 포맷: [Target Identifier(32B) + Payload]
      outputs.forEach(buf => {
        round2DirectedMessages.push({ senderPid: myPid, payload: Buffer.from(buf) });
      });
    }

    // 4. DKG Finalize
    console.log('--- DKG Finalize ---');
    const identifierMap: Record<string, number> = {};
    for (const pid of partyIds) {
       const identBytes = Buffer.from(FrostExecutor.getIdentifierBytes(pid));
       identifierMap[identBytes.toString('hex')] = pid;
    }

    for (let i = 0; i < n; i++) {
      const myPid = partyIds[i];
      const exec = executors[i];
      
      const myInputs: Buffer[] = [];
      
      round2DirectedMessages.forEach(msg => {
        const fullBuf = msg.payload;
        const targetPid = fullBuf.readUInt16BE(0);
        const packageBytes = fullBuf.subarray(2);
        
        if (targetPid === myPid) {
          // 입력 포맷 생성: [Sender PID(2B) + Payload]
          const pidBuf = Buffer.alloc(2);
          pidBuf.writeUInt16BE(msg.senderPid, 0);
          myInputs.push(Buffer.concat([pidBuf, packageBytes]));
        }
      });
      
      exec.step(myInputs);
    }

    // 공개키 확인
    const pubKeys = executors.map(e => e.getPublicKeyBytes());
    const firstKeyHex = Buffer.from(pubKeys[0]).toString('hex');
    console.log('그룹 공개키:', firstKeyHex);
    
    pubKeys.forEach(k => {
      expect(Buffer.from(k).toString('hex')).toBe(firstKeyHex);
    });

    // 5. 서명 시작 (Preprocessing)
    console.log('--- 서명 시작 ---');
    const message = Buffer.from('Hello FROST Executor!');
    const signers = [1, 2];
    const activeExecutors = executors.filter((_, idx) => signers.includes(partyIds[idx]));
    const activePids = signers;
    
    const commitmentsPayloads: { pid: number, payload: Buffer }[] = [];
    
    for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const pid = activePids[i];
        const comm = exec.startSigning(message);
        commitmentsPayloads.push({ pid, payload: Buffer.from(comm) });
    }

    // 6. 서명 Round 2
    console.log('--- 서명 Round 2 ---');
    const signatureSharesPayloads: { pid: number, payload: Buffer }[] = [];
    
    for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const myPid = activePids[i];

        // 입력: [Sender PID + Payload], 나 제외
        const inputs = commitmentsPayloads
            .filter(c => c.pid !== myPid)
            .map(c => {
                const pidBuf = Buffer.alloc(2);
                pidBuf.writeUInt16BE(c.pid, 0);
                return Buffer.concat([pidBuf, c.payload]);
        });
        
        const output = exec.step(inputs);
        // 출력: [Target PID(2B Zero) + Share Payload]
        // Broadcast이므로 앞 2바이트 제외하고 Payload 취함
        const sharePayload = Buffer.from(output[0]).subarray(2);
        signatureSharesPayloads.push({ pid: activePids[i], payload: sharePayload });
    }

    // 7. Aggregation
    console.log('--- Aggregation ---');
    let finalSignature: Buffer | null = null;
    
    for (let i = 0; i < activeExecutors.length; i++) {
        const exec = activeExecutors[i];
        const inputs = signatureSharesPayloads.map(s => {
            const pidBuf = Buffer.alloc(2);
            pidBuf.writeUInt16BE(s.pid, 0);
            return Buffer.concat([pidBuf, s.payload]);
        });
        
        exec.step(inputs);
        
        finalSignature = Buffer.from(exec.getSignature());
    }

    console.log('최종 서명 (hex):', finalSignature!.toString('hex'));

    // 8. 검증
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
    
    console.log('서명 유효성:', isValid);
    expect(isValid).toBe(true);
  });
});
