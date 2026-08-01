import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./main";

describe("superfícies de autenticação", () => {
  beforeEach(() => {
    window.history.replaceState({}, "", "/entrar");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ code: "AUTHENTICATION_REQUIRED" }), { status: 401, headers: { "Content-Type": "application/problem+json" } }));
  });

  it("mantém labels, autocomplete e ordem de teclado familiares", async () => {
    render(<App />);
    const email = await screen.findByLabelText("E-mail");
    const password = screen.getByLabelText("Senha");
    expect(email).toHaveAttribute("autocomplete", "email");
    expect(password).toHaveAttribute("autocomplete", "current-password");
    await userEvent.tab();
    expect(document.activeElement).toBe(document.querySelector(".brand"));
  });

  it("expõe cadastro e entrada como páginas, sem modal", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Entrar", level: 1 })).toBeVisible();
    expect(document.querySelector('[role="dialog"]')).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Criar conta" })).toHaveAttribute("href", "/cadastro");
  });
});
