// SPDX-License-Identifier: Apache-2.0
// LOGIN-1: the login gate renders SSO when OIDC is configured, else the no-IdP quick start.
import { render, screen, fireEvent } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const loginSpy = vi.fn();
let oidcEnabledValue = false;
vi.mock("./oidc", () => ({
  get oidcEnabled() {
    return oidcEnabledValue;
  },
  login: (...a: unknown[]) => loginSpy(...a)
}));

import { Login } from "./Login";

afterEach(() => {
  localStorage.clear();
  loginSpy.mockClear();
  window.location.hash = "";
});

describe("LOGIN-1 login gate", () => {
  it("renders 'Sign in with SSO' when OIDC is enabled and calls login()", () => {
    oidcEnabledValue = true;
    render(<Login />);
    const btn = screen.getByRole("button", { name: /sign in with sso/i });
    fireEvent.click(btn);
    expect(loginSpy).toHaveBeenCalledOnce();
  });

  it("renders the no-IdP quick start (norviq login) + paste fallback when OIDC is disabled", () => {
    oidcEnabledValue = false;
    render(<Login />);
    expect(screen.getByText(/norviq login/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/access token/i)).toBeInTheDocument();
  });

  it("stores a valid pasted token", () => {
    oidcEnabledValue = false;
    render(<Login />);
    const ta = screen.getByLabelText(/access token/i);
    fireEvent.change(ta, { target: { value: "aaa.bbb.ccc" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(localStorage.getItem("nrvq_token")).toBe("aaa.bbb.ccc");
  });
});
