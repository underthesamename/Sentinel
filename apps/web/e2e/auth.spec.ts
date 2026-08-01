import { devices, expect, test } from "@playwright/test";

const password = "sentinel-e2e-password-2026";

test("cadastro, login, restauração, logout e foco com backend real", async ({ page }) => {
  const email = `sentinel-e2e-${Date.now()}@example.test`;
  await page.goto("/cadastro");
  await expect(page.getByLabel("E-mail")).toHaveAttribute("autocomplete", "email");
  await page.getByLabel("E-mail").fill(email);
  await page.getByLabel("Senha").fill(password);
  await page.getByRole("button", { name: "Criar conta" }).click();
  await expect(page.getByText("Conta criada pelo servidor.")).toBeVisible();

  await page.getByRole("button", { name: /Ir para entrada/ }).click();
  await page.getByLabel("E-mail").fill(email);
  await page.getByLabel("Senha").fill(password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sessão em registro." })).toBeVisible();
  await expect(page.getByText(email)).toBeVisible();

  await page.reload();
  await expect(page.getByText(email)).toBeVisible();
  await page.getByRole("button", { name: /Encerrar sessão/ }).click();
  await expect(page.getByRole("heading", { name: "Entrar", level: 1 })).toBeVisible();
});

test("credenciais inválidas usam resposta genérica", async ({ page }) => {
  await page.goto("/entrar");
  await page.getByLabel("E-mail").fill(`unknown-${Date.now()}@example.test`);
  await page.getByLabel("Senha").fill(password);
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("E-mail ou senha não conferem");
});

for (const channel of ["websocket", "polling", "interrupted"] as const) {
  test(`login QR conclui com ${channel}`, async ({ browser, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== "desktop", "o caso já cria contextos desktop e mobile reais");
    const desktopContext = await browser.newContext({ baseURL });
    const mobileContext = await browser.newContext({ ...devices["Pixel 5"], baseURL });
    const desktop = await desktopContext.newPage();
    const mobile = await mobileContext.newPage();
    const email = `sentinel-qr-${channel}-${Date.now()}@example.test`;

    await mobile.goto("/cadastro");
    await mobile.getByLabel("E-mail").fill(email);
    await mobile.getByLabel("Senha").fill(password);
    await mobile.getByRole("button", { name: "Criar conta" }).click();
    await mobile.getByRole("button", { name: /Ir para entrada/ }).click();
    await mobile.getByLabel("E-mail").fill(email);
    await mobile.getByLabel("Senha").fill(password);
    await mobile.getByRole("button", { name: "Entrar", exact: true }).click();
    await expect(mobile.getByText(email)).toBeVisible();

    if (channel === "polling") {
      await desktop.routeWebSocket("**/v1/qr-login/ws", (socket) => socket.close());
    }
    await desktop.goto("/qr");
    const creationResponse = desktop.waitForResponse((response) =>
      response.url().endsWith("/v1/qr-login/challenges") && response.status() === 201
    );
    await desktop.getByRole("button", { name: /Criar pedido temporário/ }).click();
    const challenge = await (await creationResponse).json() as {
      qr_payload: string;
      verification_code: string;
    };
    await expect(desktop.getByText(challenge.verification_code)).toBeVisible();

    await mobile.goto(challenge.qr_payload);
    await mobile.getByRole("button", { name: "Continuar neste celular" }).click();
    await mobile.getByLabel("Código de quatro dígitos do desktop").fill(challenge.verification_code);
    await mobile.getByRole("button", { name: /Comparar código/ }).click();
    if (channel === "interrupted") await desktopContext.setOffline(true);
    await mobile.getByRole("button", { name: /Aprovar este desktop/ }).click();
    if (channel === "interrupted") {
      await mobile.waitForTimeout(1800);
      await desktopContext.setOffline(false);
    }

    await expect(desktop.getByText("EXCHANGED")).toBeVisible({ timeout: 12_000 });
    await desktop.getByRole("button", { name: /Ver nova sessão/ }).click();
    await expect(desktop.getByText(email)).toBeVisible();
    await desktopContext.close();
    await mobileContext.close();
  });
}
