// SPDX-License-Identifier: Apache-2.0
// LOGIN-2 (design handoff): the login gate is one component with three states — Default login
// (username/password primary + collapsible CLI token + SSO when OIDC), First login (forced change with
// strength/rules/confirm gating), and the loading/success overlay. These tests cover the real wiring:
// endpoints hit, storage honoring "keep me signed in", the must_change view switch, error/lockout
// banners, and the save gating rules.
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loginSpy = vi.fn(async (..._a: unknown[]) => undefined);
let oidcEnabledValue = false;
vi.mock("./oidc", () => ({
  get oidcEnabled() {
    return oidcEnabledValue;
  },
  login: (...a: unknown[]) => loginSpy(...a)
}));

import { Login, passwordRules, passwordStrength } from "./Login";

function mockFetch(status: number, body: unknown) {
  const fetchMock = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function fillCreds(username = "admin", password = "norviq") {
  fireEvent.change(screen.getByLabelText(/^username$/i), { target: { value: username } });
  fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: password } });
}

beforeEach(() => {
  oidcEnabledValue = false;
  // The login screen now opens with a branded boot splash that probes /readyz on mount. Give every test a
  // default readiness response so that probe resolves cleanly; tests that assert on a specific endpoint
  // re-stub fetch via mockFetch() before rendering (that stub then also answers the boot probe).
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ status: "ready" }), { status: 200, headers: { "Content-Type": "application/json" } }))
  );
});
afterEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  loginSpy.mockClear();
  vi.restoreAllMocks();
  window.location.hash = "";
});

describe("password rules/strength (spec formulas)", () => {
  it("scores and gates per the design", () => {
    expect(passwordStrength("")).toBe(0);
    expect(passwordStrength("Str0ng-Passphrase!")).toBeGreaterThanOrEqual(70);
    expect(passwordRules("short")).toEqual([false, false, false]);
    expect(passwordRules("alllowercaseonly")).toEqual([true, false, false]);
    expect(passwordRules("NewStr0ng-Pass")).toEqual([true, true, true]);
  });
});

describe("boot splash (brand moment on every load)", () => {
  it("plays the branded splash on mount, then reveals the form", async () => {
    mockFetch(200, { status: "ready", db: true, redis: true });
    render(<Login />);
    // a fresh page load opens on the shared BrandLoader (role=status, "Loading Norviq") — NO status text.
    const splash = screen.getByRole("status", { name: /loading norviq/i });
    expect(splash).toBeInTheDocument();
    expect(screen.queryByText(/starting norviq/i)).toBeNull();
    expect(screen.queryByText(/connecting to the security backend/i)).toBeNull();
    // …and it auto-dismisses (time-based) to the sign-in form
    await waitFor(() => expect(screen.queryByRole("status", { name: /loading norviq/i })).toBeNull());
    expect(screen.getByRole("button", { name: /^sign in$/i })).toBeInTheDocument();
  });
});

describe("default login view", () => {
  it("renders username/password as the primary form; Sign in disabled until both filled", () => {
    render(<Login />);
    const btn = screen.getByRole("button", { name: /^sign in$/i });
    expect(btn).toBeDisabled();
    fillCreds();
    expect(btn).toBeEnabled();
  });

  it("posts to /api/v1/auth/login and stores the token in sessionStorage by default", async () => {
    const f = mockFetch(200, { access_token: "hdr.body.sig", must_change: false });
    render(<Login />);
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await waitFor(() => expect(sessionStorage.getItem("nrvq_token")).toBe("hdr.body.sig"));
    expect(localStorage.getItem("nrvq_token")).toBeNull(); // remember unchecked -> session-scoped
    // (the boot /readyz probe fires first, so find the login call by URL rather than assuming index 0)
    const call = f.mock.calls.find((c) => String(c[0]).includes("/api/v1/auth/login"))!;
    expect(call).toBeTruthy();
    expect(JSON.parse(call[1]!.body as string)).toEqual({ username: "admin", password: "norviq" });
  });

  it("L4: the brand lockup is CENTERED (not left-aligned)", () => {
    render(<Login />);
    const wordmark = screen.getByText("norviq");
    const lockup = wordmark.parentElement as HTMLElement; // the flex row wrapping the mark + wordmark
    expect(lockup).toHaveStyle({ justifyContent: "center" });
  });

  it("L2: the Sign in button shows the shared BrandLoader (aria-busy), replacing the 'Signing in…' text", async () => {
    // hang the /auth/login request so the signing state persists long enough to assert
    let release!: () => void;
    const pending = new Promise<Response>((r) => (release = () => r({ ok: true, json: () => Promise.resolve({ access_token: "a.b.c", must_change: false }) } as Response)));
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes("/readyz")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: "ready", db: true, redis: true }) } as Response);
      }
      return pending; // /auth/login stays in flight → phase === "signing"
    });
    render(<Login />);
    await waitFor(() => expect(screen.getByRole("button", { name: /^sign in$/i })).toBeInTheDocument());
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => {
      const busyBtn = document.querySelector('button.nv-primary[aria-busy="true"]') as HTMLElement | null;
      expect(busyBtn).toBeTruthy();
      // the loading state is LOGO-ONLY: the shared loader is inside the button…
      const loader = busyBtn!.querySelector('[data-testid="brand-loader"]') as HTMLElement | null;
      expect(loader).toBeTruthy();
      // …with NO visible "Signing in" text node (it must not appear on screen)…
      expect(within(busyBtn!).queryByText(/Signing in/)).toBeNull();
      expect(within(busyBtn!).queryByText(/^Sign in$/)).toBeNull();
      // …but the sr-only accessible label is still present for assistive tech (aria-label on role=status)
      expect(loader!.getAttribute("aria-label")).toBe("Signing in");
    });
    release();
  });

  it("B1: the token/CLI submit ALSO shows the shared BrandLoader (same in-flight path, aria-busy)", async () => {
    // the token path validates against /me; hang it so the signing state persists
    let release!: () => void;
    const pending = new Promise<Response>((r) => (release = () => r({ ok: true, json: () => Promise.resolve({ sub: "x", role: "admin" }) } as Response)));
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes("/readyz")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: "ready", db: true, redis: true }) } as Response);
      }
      return pending; // /me stays in flight → phase === "signing"
    });
    render(<Login />);
    await waitFor(() => expect(screen.getByRole("button", { name: /Use a token \/ CLI/i })).toBeInTheDocument());
    // open the token field and submit a token (NO username/password → the token path)
    fireEvent.click(screen.getByRole("button", { name: /Use a token \/ CLI/i }));
    fireEvent.change(screen.getByLabelText("Access token"), { target: { value: "nrvq_dev_faketoken_123" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => {
      const busyBtn = document.querySelector('button.nv-primary[aria-busy="true"]') as HTMLElement | null;
      expect(busyBtn, "token submit must show the in-flight loader").toBeTruthy();
      const loader = busyBtn!.querySelector('[data-testid="brand-loader"]') as HTMLElement | null;
      expect(loader).toBeTruthy();
      // logo-only on the token path too: no visible "Signing in"/"Sign in" text, sr-only aria-label present
      expect(within(busyBtn!).queryByText(/Signing in/)).toBeNull();
      expect(within(busyBtn!).queryByText(/^Sign in$/)).toBeNull();
      expect(loader!.getAttribute("aria-label")).toBe("Signing in");
    });
    release();
  });

  it("A1: signIn holds the loader for the MIN even when auth resolves instantly (fake timers)", async () => {
    vi.useFakeTimers();
    // both /readyz (boot) and /auth/login resolve INSTANTLY — the only thing that keeps the loader up is the min
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes("/readyz")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: "ready", db: true, redis: true }) } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ access_token: "min.token.sig", must_change: false }) } as Response);
    });
    render(<Login />);
    await vi.advanceTimersByTimeAsync(200); // past the boot splash (≤150ms) → the sign-in form
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    // auth already resolved (microtask), but the 400ms min has NOT elapsed → the loader is still up
    await vi.advanceTimersByTimeAsync(100); // 100 < 400
    expect(document.querySelector('button.nv-primary[aria-busy="true"]'), "loader must persist before the min").toBeTruthy();
    expect(document.querySelector('[data-testid="brand-loader"]')).toBeTruthy();
    expect(sessionStorage.getItem("nrvq_token")).toBeNull(); // NOT transitioned yet

    // cross the min → signIn proceeds (token stored) and the success state begins
    await vi.advanceTimersByTimeAsync(400); // total 500 > 400
    expect(sessionStorage.getItem("nrvq_token")).toBe("min.token.sig");
    vi.useRealTimers();
  });

  it("LOGO-ONLY overlay (busy/signing): no visible 'Establishing secure session' caption; sr-only aria-label carries it", async () => {
    // hang /auth/login so the overlay's signing state persists long enough to assert
    let release!: () => void;
    const pending = new Promise<Response>((r) => (release = () => r({ ok: true, json: () => Promise.resolve({ access_token: "a.b.c", must_change: false }) } as Response)));
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes("/readyz")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: "ready", db: true, redis: true }) } as Response);
      }
      return pending; // /auth/login stays in flight → phase === "signing" → overlay busy
    });
    render(<Login />);
    await waitFor(() => expect(screen.getByRole("button", { name: /^sign in$/i })).toBeInTheDocument());
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() => {
      const overlay = document.querySelector('[role="dialog"]') as HTMLElement | null;
      expect(overlay, "the full-screen overlay must appear while signing").toBeTruthy();
      // the overlay shows ONLY the shared logo — its status loader is the sole child…
      const loader = overlay!.querySelector('[data-testid="brand-loader"]') as HTMLElement | null;
      expect(loader).toBeTruthy();
      // …with NO visible caption text node on screen…
      expect(within(overlay!).queryByText(/Establishing secure session/i)).toBeNull();
      expect(within(overlay!).queryByText(/Signing in/i)).toBeNull();
      // …but the sr-only accessible name is announced to assistive tech (aria-label on role=status).
      expect(loader!.getAttribute("role")).toBe("status");
      expect(loader!.getAttribute("aria-label")).toMatch(/establishing secure session/i);
    });
    release();
  });

  it("LOGO-ONLY overlay (done/success): no visible 'Signed in' / 'Session established…' caption, no ✓, no button; aria-label carries it", async () => {
    vi.useFakeTimers();
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes("/readyz")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: "ready", db: true, redis: true }) } as Response);
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ access_token: "done.token.sig", must_change: false }) } as Response);
    });
    render(<Login />);
    await vi.advanceTimersByTimeAsync(200); // past the boot splash → the sign-in form
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    // cross the 400ms min → finish("done_sign"): the success overlay shows (the 900ms redirect is NOT yet due)
    await vi.advanceTimersByTimeAsync(500);

    const overlay = document.querySelector('[role="dialog"]') as HTMLElement | null;
    expect(overlay, "the success overlay must be present after sign-in resolves").toBeTruthy();
    // LOGO-ONLY: none of the success chrome renders visibly — no caption, no check glyph, no back button.
    expect(within(overlay!).queryByText(/Signed in/i)).toBeNull();
    expect(within(overlay!).queryByText(/Session established/i)).toBeNull();
    expect(within(overlay!).queryByText("✓")).toBeNull();
    expect(within(overlay!).queryByRole("button", { name: /back to sign in/i })).toBeNull();
    // the centered logo is the only thing shown; the caption is carried sr-only via aria-label.
    const loader = overlay!.querySelector('[data-testid="brand-loader"]') as HTMLElement | null;
    expect(loader).toBeTruthy();
    expect(loader!.getAttribute("role")).toBe("status");
    expect(loader!.getAttribute("aria-label")).toMatch(/signed in, session established/i);
    vi.useRealTimers();
  });

  it("honors 'Keep me signed in' by storing in localStorage", async () => {
    mockFetch(200, { access_token: "a.b.c", must_change: false });
    render(<Login />);
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /keep me signed in/i }));
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await waitFor(() => expect(localStorage.getItem("nrvq_token")).toBe("a.b.c"));
    expect(sessionStorage.getItem("nrvq_token")).toBeNull();
  });

  it("switches to the First-login view (instead of proceeding) when must_change is flagged", async () => {
    mockFetch(200, { access_token: "a.b.c", must_change: true, default_password_in_use: true });
    render(<Login />);
    fillCreds();
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByText(/set a new password/i);
    expect(localStorage.getItem("nrvq_must_change")).toBe("1");
    // current password is prefilled from the login they just completed
    expect(screen.getByLabelText(/current password/i)).toHaveValue("norviq");
  });

  it("shows a generic error on 401 and a lockout message on 429", async () => {
    mockFetch(401, { detail: "Invalid username or password" });
    render(<Login />);
    fillCreds("admin", "wrong");
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByText(/invalid username or password/i);
    expect(sessionStorage.getItem("nrvq_token")).toBeNull();

    mockFetch(429, { detail: "Too many failed attempts" });
    fireEvent.change(screen.getByLabelText(/^password$/i), { target: { value: "wrong2" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByText(/too many failed attempts/i);
  });

  it("validates a CLI token against /api/v1/me and signs in on 200", async () => {
    const f = mockFetch(200, { sub: "cli-admin", role: "admin" });
    render(<Login />);
    fireEvent.click(screen.getByRole("button", { name: /use a token \/ cli/i }));
    fireEvent.change(screen.getByLabelText(/access token/i), { target: { value: "aaa.bbb.ccc" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await waitFor(() => expect(sessionStorage.getItem("nrvq_token")).toBe("aaa.bbb.ccc"));
    const call = f.mock.calls.find((c) => String(c[0]).includes("/api/v1/me"))!;
    expect(call).toBeTruthy();
    expect((call[1]!.headers as Record<string, string>).Authorization).toBe("Bearer aaa.bbb.ccc");
  });

  it("rejects an invalid CLI token with an error banner", async () => {
    mockFetch(401, { detail: "Invalid token" });
    render(<Login />);
    fireEvent.click(screen.getByRole("button", { name: /use a token \/ cli/i }));
    fireEvent.change(screen.getByLabelText(/access token/i), { target: { value: "bad.token.here" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByText(/token is not valid/i);
    expect(sessionStorage.getItem("nrvq_token")).toBeNull();
  });

  it("keeps SSO discoverable but disabled (with setup hint) until an IdP is configured", () => {
    render(<Login />);
    const btn = screen.getByRole("button", { name: /sign in with sso/i });
    expect(btn).toBeDisabled();
    expect(screen.getByText(/isn.t configured yet/i)).toBeInTheDocument();
    fireEvent.click(btn);
    expect(loginSpy).not.toHaveBeenCalled();
  });

  it("enables SSO and starts the real flow once OIDC is configured", () => {
    oidcEnabledValue = true;
    render(<Login />);
    const btn = screen.getByRole("button", { name: /sign in with sso/i });
    expect(btn).toBeEnabled();
    expect(screen.queryByText(/isn.t configured yet/i)).toBeNull();
    fireEvent.click(btn);
    expect(loginSpy).toHaveBeenCalledOnce();
  });

  it("renders no manual view switcher — the first-login view is server-driven only", () => {
    render(<Login />);
    expect(screen.queryByRole("button", { name: /^first login$/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /^default login$/i })).toBeNull();
    expect(screen.queryByText(/set a new password/i)).toBeNull();
  });

  it("shows the default-password banner when the account is known to be on the default credential", () => {
    localStorage.setItem("nrvq_must_change", "1");
    render(<Login />);
    // no token -> still the default view, banner visible
    expect(screen.getByText(/default password in use/i)).toBeInTheDocument();
  });
});

describe("first login (forced change) view", () => {
  function renderFirst() {
    localStorage.setItem("nrvq_token", "hdr.body.sig");
    localStorage.setItem("nrvq_must_change", "1");
    render(<Login />);
  }

  it("opens directly on the change view for a session flagged must_change", () => {
    renderFirst();
    expect(screen.getByText(/set a new password/i)).toBeInTheDocument();
  });

  it("gates Save on rules + confirm match, with live chips", () => {
    renderFirst();
    const save = screen.getByRole("button", { name: /save & continue/i });
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "norviq" } });
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "weak" } });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "NewStr0ng-Passphrase" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "different" } });
    expect(save).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "NewStr0ng-Passphrase" } });
    expect(save).toBeEnabled();
  });

  it("posts to change-password with the bearer token and clears must_change on success", async () => {
    const f = mockFetch(200, { changed: true, must_change: false });
    renderFirst();
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "norviq" } });
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "NewStr0ng-Passphrase" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "NewStr0ng-Passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: /save & continue/i }));
    await waitFor(() => expect(localStorage.getItem("nrvq_must_change")).toBeNull());
    const call = f.mock.calls.find((c) => String(c[0]).includes("/api/v1/auth/change-password"))!;
    expect(call).toBeTruthy();
    expect((call[1]!.headers as Record<string, string>).Authorization).toBe("Bearer hdr.body.sig");
    expect(JSON.parse(call[1]!.body as string)).toEqual({
      current_password: "norviq",
      new_password: "NewStr0ng-Passphrase"
    });
  });

  it("surfaces the server's validation error and keeps must_change set", async () => {
    mockFetch(401, { detail: "Current password is incorrect" });
    renderFirst();
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "wrong" } });
    fireEvent.change(screen.getByLabelText(/^new password$/i), { target: { value: "NewStr0ng-Passphrase" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "NewStr0ng-Passphrase" } });
    fireEvent.click(screen.getByRole("button", { name: /save & continue/i }));
    await screen.findByText(/current password is incorrect/i);
    expect(localStorage.getItem("nrvq_must_change")).toBe("1");
  });

  it("offers no manual escape hatch — the change screen stays until the password is changed", () => {
    renderFirst();
    expect(screen.queryByRole("button", { name: /^default login$/i })).toBeNull();
    expect(screen.getByText(/set a new password/i)).toBeInTheDocument();
  });
});
