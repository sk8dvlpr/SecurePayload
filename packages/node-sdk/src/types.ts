export type Mode = 'hmac' | 'aead' | 'both';
export type SignAlg = 'hmac' | 'ed25519';

export interface VerifyResult {
  ok: boolean;
  status?: number;
  error?: string;
  debug?: Record<string, unknown>;
  mode?: string;
  bodyPlain?: string | null;
  json?: unknown;
}

export interface SecurePayloadNodeOptions {
  mode?: Mode;
  signAlg?: SignAlg;
  version?: string;
  clientId?: string;
  keyId?: string;
  hmacSecretRaw?: string | null;
  aeadKeyB64?: string | null;
  ed25519SecretKeyB64?: string | null;
  ed25519PublicKeyB64?: string | null;
  ed25519SecretKeyServerB64?: string | null;
  ed25519PublicKeyServerB64?: string | null;
  deriveKeys?: boolean;
  bindHeaders?: string[];
  replayTtl?: number;
  clockSkew?: number;
  keyLoader?: ((clientId: string, keyId: string) => {
    hmacSecret?: string | null;
    aeadKeyB64?: string | null;
    ed25519PublicKeyB64?: string | null;
    ed25519SecretKeyServerB64?: string | null;
    ed25519PublicKeyServerB64?: string | null;
  }) | null;
  replayStore?: ((cacheKey: string, ttl: number) => boolean) | null;
  clock?: () => number;
  nonceGenerator?: () => string;
  respNonceGenerator?: () => string;
}

export class SecurePayloadError extends Error {
  constructor(public readonly status: number, message: string, public readonly context: Record<string, unknown> = {}) {
    super(message);
  }
}
