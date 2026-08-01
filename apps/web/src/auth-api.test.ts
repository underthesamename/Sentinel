import { describe, expect, it, vi } from "vitest";
import { ApiError, authApi } from "./auth-api";
import { apiMessage } from "./main";

describe("authApi", () => {
  it("envia credenciais sem armazenar tokens no JavaScript", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ id: "user", email: "ana@example.com" }), { status: 201 }));

    await authApi.register("ana@example.com", "uma-senha-longa-e-segura");

    expect(fetchMock).toHaveBeenCalledWith("/v1/auth/register", expect.objectContaining({ credentials: "include", method: "POST" }));
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ email: "ana@example.com", password: "uma-senha-longa-e-segura" });
    fetchMock.mockRestore();
  });

  it("obtém CSRF antes do logout", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: "csrf-value" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    await authApi.logout();

    expect(fetchMock.mock.calls[0][0]).toBe("/v1/auth/csrf");
    expect(fetchMock.mock.calls[1]).toEqual(["/v1/auth/logout", expect.objectContaining({ method: "POST", headers: { Accept: "application/json", "X-CSRF-Token": "csrf-value" } })]);
    fetchMock.mockRestore();
  });
});

describe("mensagens de autenticação", () => {
  it("não distingue conta inexistente de senha incorreta", () => {
    expect(apiMessage(new ApiError(401, "INVALID_CREDENTIALS"), "login")).toBe("E-mail ou senha não conferem. Revise os dados e tente novamente.");
  });

  it("distingue serviço indisponível e sessão expirada", () => {
    expect(apiMessage(new ApiError(503, "SERVICE_NOT_READY"), "login")).toContain("indisponível");
    expect(apiMessage(new ApiError(401, "AUTHENTICATION_REQUIRED"), "session")).toContain("sessão terminou");
  });
});
