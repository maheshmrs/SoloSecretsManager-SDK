export class SSMError extends Error {}
export interface ClientOptions {
  url: string;
  serverId: string;
  pin: string;
  environmentId: string;
  ciKey: string;
  ttlMs?: number;
  credential?: (audience: string) => Promise<string>;
  kind?: "github" | "gitlab";
  cloud?: AWS | Azure | GCP | null;
}
export class CloudError extends Error {}
export class AWS { constructor(keyArn: string, stsEndpoint?: string); }
export class Azure { constructor(keyUrl: string, audience: string); }
export class GCP { constructor(keyVersion: string); }
export function gitlabToken(): Promise<string>;
export class Client {
  constructor(opts: ClientOptions);
  static fromEnv(opts?: Partial<ClientOptions>): Client;
  get(name: string): Promise<string>;
  all(): Promise<Record<string, string>>;
}
export function githubToken(audience: string): Promise<string>;
export function decryptExchange(ciKey: string, environmentId: string, exchange: unknown): Record<string, string>;
export function verifyAttestation(a: unknown, pin: string, serverId: string, connPin: string): Set<string>;
