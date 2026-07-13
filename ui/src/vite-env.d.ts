/// <reference types="vite/client" />

// SLIM-MONACO: the minimal editor-core entry (used by lib/monaco.ts to avoid bundling all built-in
// languages) is exposed only through monaco-editor's "./*" wildcard export, which carries no `types`
// condition — so tsc (moduleResolution: Bundler) can't find its declarations even though the .d.ts
// exists on disk and Vite resolves it fine. Point the deep path at the package's root types.
declare module "monaco-editor/esm/vs/editor/editor.api" {
  export * from "monaco-editor";
}

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

// F-25 + LOGIN-1: runtime config injected by the container entrypoint (config.js) — see ui/docker-entrypoint.sh.
interface Window {
  __NRVQ_CONFIG__?: {
    fleetApiUrl?: string;
    oidcIssuer?: string;
    oidcClientId?: string;
    oidcRedirectUri?: string;
    // LOGIN-2: human-readable IdP name for login copy ("Redirecting to Okta…"). Optional; falls back to "SSO".
    oidcProviderName?: string;
  };
}
