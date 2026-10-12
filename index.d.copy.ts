/* tslint:disable */
/* eslint-disable */

export interface DkgPart1Output {
  secretPackage: Buffer
  round1Package: Buffer
}

export interface DkgPart1HandleOutput {
  secretPackage: unknown
  round1Package: Buffer
}

export interface DkgPart2Output {
  secretPackage: Buffer
  round2Packages: Record<string, Buffer>
}

export interface DkgPart2HandleOutput {
  secretPackage: unknown
  round2Packages: Record<string, Buffer>
}

export interface DkgPart3Output {
  keyPackage: Buffer
  pubkeyPackage: Buffer
}

export interface DkgPart3HandleOutput {
  keyPackage: unknown
  pubkeyPackage: Buffer
}

export interface SignPart1Output {
  nonces: Buffer
  commitments: Buffer
}

export interface SignPart1HandleOutput {
  nonces: unknown
  commitments: Buffer
}

export class FrostDkgState {
  static dkgPart1(partyId: number, maxSigners: number, minSigners: number): DkgPart1Output
  static dkgPart1Handle(partyId: number, maxSigners: number, minSigners: number): DkgPart1HandleOutput
  static dkgPart2(secretPackageBin: Buffer, round1PackagesMap: Record<string, Buffer>): DkgPart2Output
  static dkgPart2Handle(secretPackage: unknown, round1PackagesMap: Record<string, Buffer>): DkgPart2HandleOutput
  static dkgPart3(secretPackageBin: Buffer, round1PackagesMap: Record<string, Buffer>, round2PackagesMap: Record<string, Buffer>): DkgPart3Output
  static dkgPart3Handle(secretPackage: unknown, round1PackagesMap: Record<string, Buffer>, round2PackagesMap: Record<string, Buffer>): DkgPart3HandleOutput
  static getPublicKeyBytes(pubkeyPackageBin: Buffer): Buffer
  static getIdentifier(partyId: number): string
}

export class FrostSigningState {
  static signPart1(keyPackageBin: Buffer): SignPart1Output
  static signPart1Handle(keyPackage: unknown): SignPart1HandleOutput
  static signPart2(signingPackageBin: Buffer, noncesBin: Buffer, keyPackageBin: Buffer): Buffer
  static signPart2Handle(signingPackageBin: Buffer, nonces: unknown, keyPackage: unknown): Buffer
  static createSigningPackage(message: Buffer, commitmentsMap: Record<string, Buffer>): Buffer
  static aggregate(signingPackageBin: Buffer, signatureSharesMap: Record<string, Buffer>, pubkeyPackageBin: Buffer): Buffer
}

export class FrostExecutor {
  constructor(partyId: number, numSigners: number, threshold: number)
  isDestroyed(): boolean
  is_destroyed(): boolean
  destroy(): void
  startKeygen(): Buffer
  startSigning(message: Buffer, signers?: Array<number> | null): Buffer
  step(inputs: Array<Buffer>): Array<Buffer>
  stepAsync(inputs: Array<Buffer>): Promise<Array<Buffer>>
  step_async(inputs: Array<Buffer>): Promise<Array<Buffer>>
  getPublicKeyBytes(): Buffer
  getSignature(): Buffer
  exportKeyshare(): Buffer
  importKeyshare(data: Buffer): void
  exportKeyshareHandle(): unknown
  importKeyshareHandle(handle: unknown): void
  exportKeyPackageHandle(): unknown
  importKeyPackageHandle(handle: unknown, pubkeyPackageBin?: Buffer | null): void
  static getIdentifierBytes(partyId: number): Buffer
}
