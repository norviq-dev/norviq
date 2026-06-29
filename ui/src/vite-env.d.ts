/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly DEV: boolean;
  readonly PROD: boolean;
  readonly MODE: string;
  readonly VITE_DEV_TOKEN?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_ENV_LABEL?: string;
  // OIDC SSO (A3). When VITE_OIDC_ISSUER + VITE_OIDC_CLIENT_ID are set, the console logs in via
  // Auth Code + PKCE instead of the dev token. VITE_OIDC_REDIRECT_URI defaults to origin/auth/callback.
  readonly VITE_OIDC_ISSUER?: string;
  readonly VITE_OIDC_CLIENT_ID?: string;
  readonly VITE_OIDC_REDIRECT_URI?: string;
  // Multi-cluster fleet (F045). Set to a fleet-api hub URL to enable the cross-cluster Fleet view.
  readonly VITE_FLEET_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
