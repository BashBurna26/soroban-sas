// A minimal, real client for the SAS and Schema Registry contracts.
//
// Rather than hand-encoding each contract function's ScVal argument list,
// this builds on `@stellar/stellar-sdk/contract`'s `Client`, which fetches
// the deployed contract's on-chain XDR spec (`Client.from({ contractId,
// rpcUrl, ... })`) and uses it to convert plain JS values into the exact
// InvokeHostFunction operation the contract expects — the same approach
// `stellar-cli`'s `contract invoke` and generated TS contract clients use.
// This defers argument encoding to code that reads the contract's own
// metadata, rather than this package guessing struct layouts by hand.
//
// Scope note: the `UID` newtype (`soroban_sas_common::UID(BytesN<32>)`) is
// passed here as a one-element array wrapping its 32 bytes, matching the
// "single-element ScVec" shape documented in
// packages/soroban-sas-sdk/src/events.rs's `decode_uid`. This has not been
// exercised against a live RPC node in this environment — see
// packages/soroban-sas-js/README.md's "Scope and limitations" section.

import { Buffer } from "buffer";
import { Client as ContractClient } from "@stellar/stellar-sdk/contract";
import type { ClientOptions, SignTransaction } from "@stellar/stellar-sdk/contract";
import type { Attestation, DelegatedAttestation, SchemaRecord, UID } from "./types.js";
import { ResilientTransport } from "./resilient.js";
import type { EndpointConfig, ResilienceOptions } from "./resilient.js";

export interface SASClientConfig {
  /** SAS contract id (C...). */
  contractId: string;
  /** Schema Registry contract id (C...); required for schema methods. */
  registryContractId?: string;
  /** Indexer contract id (C...); required for recipient/schema/attester index lookups. */
  indexerContractId?: string;
  /** Soroban RPC URL. Required unless `endpoints` is given. */
  rpcUrl?: string;
  /**
   * Multiple RPC endpoints with priority weights. Reads fail over between them
   * (429/502/503/504, timeouts, network errors); writes go to one endpoint,
   * once. When set, replaces `rpcUrl`.
   */
  endpoints?: EndpointConfig[];
  /** Timeouts, retries, backoff, health thresholds, telemetry hook. */
  resilience?: ResilienceOptions;
  networkPassphrase: string;
  /** Account (G...) that pays for and authorizes submitted transactions. */
  publicKey?: string;
  /** Browser wallet callback used to sign and optionally submit transactions. */
  signTransaction?: SignTransaction;
  /** Optional SEP-43 authorization signer for multi-auth invocations. */
  signAuthEntry?: ClientOptions["signAuthEntry"];
  /** Secret seed (S...); prohibited in browser contexts. */
  secret?: string;
}

export interface SubmitResult {
  hash: string;
}

function uidArg(uid: UID): [Buffer] {
  return [Buffer.from(uid, "hex")];
}

function attestationArg(a: Attestation): Record<string, unknown> {
  return {
    uid: uidArg(a.uid),
    schema_uid: uidArg(a.schemaUid),
    time: a.time,
    expiration_time: a.expirationTime,
    revocation_time: a.revocationTime,
    ref_uid: uidArg(a.refUid),
    recipient: a.recipient,
    attester: a.attester,
    revocable: a.revocable,
    data: Buffer.from(a.data),
  };
}

/** Client for `SAS::*` and `SchemaRegistry::*` contract entry points. */
export class SASClient {
  private readonly clients = new Map<string, Promise<ContractClient>>();
  /** Endpoint health, failover routing and telemetry (`transport.on(...)`). */
  readonly transport: ResilientTransport;

  constructor(private readonly config: SASClientConfig) {
    const endpoints = config.endpoints ?? (config.rpcUrl ? [{ url: config.rpcUrl }] : []);
    if (endpoints.length === 0) throw new Error("SASClientConfig requires rpcUrl or endpoints");
    this.transport = new ResilientTransport(endpoints, config.resilience);
  }

  private publicKey(): string | undefined {
    return this.config.publicKey;
  }

  /** Contract client bound to one endpoint (cached; a failed build is not cached). */
  private clientFor(contractId: string, rpcUrl: string): Promise<ContractClient> {
    const key = `${rpcUrl}|${contractId}`;
    let c = this.clients.get(key);
    if (!c) {
      c = ContractClient.from({
        contractId,
        rpcUrl,
        networkPassphrase: this.config.networkPassphrase,
        publicKey: this.publicKey(),
        signTransaction: this.config.signTransaction,
        signAuthEntry: this.config.signAuthEntry,
      });
      c.catch(() => this.clients.delete(key));
      this.clients.set(key, c);
    }
    return c;
  }

  private registryId(): string {
    if (!this.config.registryContractId) {
      throw new Error("SASClientConfig.registryContractId is required for schema methods");
    }
    return this.config.registryContractId;
  }

  private indexerId(): string {
    if (!this.config.indexerContractId) {
      throw new Error("SASClientConfig.indexerContractId is required for indexer methods");
    }
    return this.config.indexerContractId;
  }

  /** Read-only call: simulated, so safe to retry on any endpoint. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private read<T>(contractId: string, call: (client: any) => Promise<T>): Promise<T> {
    return this.transport.read(async (url) => call(await this.clientFor(contractId, url)));
  }

  /** State-changing call: built and submitted on one endpoint, exactly once. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private write<T>(contractId: string, call: (client: any) => Promise<T>): Promise<T> {
    return this.transport.write(async (url) => call(await this.clientFor(contractId, url)));
  }

  /** Reads indexed UIDs for a recipient without submitting a transaction. */
  async getRecipientAttestations(recipient: string): Promise<UID[]> {
    return this.read(this.indexerId(), async (client) => {
      // The contract's Vec<UID> decodes to one-element arrays of 32-byte buffers.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tx = await (client as any).get_attestations_by_recipient({ recipient });
      if (!Array.isArray(tx.result)) {
        throw new Error("Indexer returned malformed recipient attestation UIDs");
      }
      return tx.result.map((value: unknown): UID => {
        const bytes = Array.isArray(value) && value.length === 1 ? value[0] : null;
        if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
          throw new Error("Indexer returned a malformed attestation UID");
        }
        return Buffer.from(bytes).toString("hex");
      });
    });
  }
  /** Calls `SchemaRegistry::register(owner, schema, resolver, revocable)`. */
  async registerSchema(schema: string, resolver: string, revocable: boolean): Promise<UID> {
    const owner = this.publicKey();
    if (!owner) throw new Error("registerSchema requires config.publicKey");
    const sent = await this.write(this.registryId(), async (client) => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tx = await (client as any).register({ owner, schema, resolver, revocable });
      return tx.signAndSend();
    });
    return Buffer.from(sent.result as unknown as Uint8Array).toString("hex");
  }

  /** Calls `SchemaRegistry::get_schema(uid)`. Read-only (simulated, not submitted). */
  async getSchema(uid: UID): Promise<SchemaRecord | null> {
    const result = await this.read(this.registryId(), async (client) => (await client.get_schema({ uid: uidArg(uid) })).result);
    const record = result as unknown as
      | { uid: [Buffer]; resolver: string; revocable: boolean; schema: string }
      | null;
    if (!record) return null;
    return {
      uid: Buffer.from(record.uid[0]).toString("hex"),
      resolver: record.resolver,
      revocable: record.revocable,
      schema: record.schema,
    };
  }

  /** Calls `SAS::attest(attestation)` and submits the signed transaction. */
  async attest(attestation: Attestation): Promise<SubmitResult> {
    const sent = await this.write(this.config.contractId, async (client) => {
      const tx = await client.attest({ attestation: attestationArg(attestation) });
      return tx.signAndSend();
    });
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::attest_by_delegation`, relaying an off-chain-signed attestation. */
  async attestByDelegation(delegated: DelegatedAttestation): Promise<SubmitResult> {
    const sent = await this.write(this.config.contractId, async (client) => {
      const tx = await client.attest_by_delegation({
        attestation: attestationArg(delegated.attestation),
        nonce: delegated.nonce,
        signature: Buffer.from(delegated.signature),
        public_key: Buffer.from(delegated.publicKey),
      });
      return tx.signAndSend();
    });
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::revoke(uid)`. */
  async revoke(uid: UID): Promise<SubmitResult> {
    const sent = await this.write(this.config.contractId, async (client) => {
      const tx = await client.revoke({ uid: uidArg(uid) });
      return tx.signAndSend();
    });
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::get_attestation(uid)`. Read-only (simulated, not submitted). */
  async getAttestation(uid: UID): Promise<Attestation | null> {
    const result = await this.read(this.config.contractId, async (client) => (await client.get_attestation({ uid: uidArg(uid) })).result);
    const raw = result as unknown as
      | {
          uid: [Buffer];
          schema_uid: [Buffer];
          time: bigint;
          expiration_time: bigint;
          revocation_time: bigint;
          ref_uid: [Buffer];
          recipient: string;
          attester: string;
          revocable: boolean;
          data: Buffer;
        }
      | null;
    if (!raw) return null;
    return {
      uid: Buffer.from(raw.uid[0]).toString("hex"),
      schemaUid: Buffer.from(raw.schema_uid[0]).toString("hex"),
      time: raw.time,
      expirationTime: raw.expiration_time,
      revocationTime: raw.revocation_time,
      refUid: Buffer.from(raw.ref_uid[0]).toString("hex"),
      recipient: raw.recipient,
      attester: raw.attester,
      revocable: raw.revocable,
      data: new Uint8Array(raw.data),
    };
  }

  /** Calls `Indexer::get_attestations_by_recipient(recipient)`. Read-only (simulated). */
  async getAttestationUidsByRecipient(recipient: string): Promise<UID[]> {
    return this.getRecipientAttestations(recipient);
  }

  /** Fetches all `Attestation` records indexed under `recipient`. */
  async getAttestationsByRecipient(recipient: string): Promise<Attestation[]> {
    const uids = await this.getAttestationUidsByRecipient(recipient);
    if (uids.length === 0) return [];
    const records = await Promise.all(uids.map((uid) => this.getAttestation(uid)));
    return records.filter((item): item is Attestation => item !== null);
  }
}
