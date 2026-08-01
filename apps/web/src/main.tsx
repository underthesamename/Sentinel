import { StrictMode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import QRCode from "qrcode";
import { ApiError, authApi, type SessionResponse } from "./auth-api";
import { qrApi, type QrChallengeCreated, type QrDetails, type QrSnapshot } from "./qr-api";
import "./styles.css";

type Route = "home" | "register" | "login" | "account" | "qrDesktop" | "qrScan" | "qrCamera" | "qrConfirm";
type SessionState =
  | { status: "loading" }
  | { status: "anonymous"; notice?: string }
  | { status: "authenticated"; value: SessionResponse };

const states = ["CREATED", "SCANNED", "APPROVED", "EXCHANGED"];
const stages = [
  { title: "Desktop solicita", body: "Cria um challenge temporário e exibe QR Code e código de confirmação." },
  { title: "Celular confirma", body: "Escaneia, compara o código e registra uma decisão explícita do usuário." },
  { title: "Servidor persiste", body: "Valida transições e concorrência no PostgreSQL, a fonte de verdade." },
  { title: "Sessão é trocada", body: "O desktop conclui por HTTP exatamente uma vez, mesmo após perder o WebSocket." },
];

function routeFromPath(pathname: string): Route {
  if (pathname === "/cadastro") return "register";
  if (pathname === "/entrar") return "login";
  if (pathname === "/conta") return "account";
  if (pathname === "/qr") return "qrDesktop";
  if (pathname === "/qr/scan") return "qrScan";
  if (pathname === "/qr/camera") return "qrCamera";
  if (pathname.startsWith("/qr/confirm/")) return "qrConfirm";
  return "home";
}

function pathForRoute(route: Route) {
  const paths: Record<Route, string> = {
    home: "/",
    register: "/cadastro",
    login: "/entrar",
    account: "/conta",
    qrDesktop: "/qr",
    qrScan: "/qr/scan",
    qrCamera: "/qr/camera",
    qrConfirm: window.location.pathname.startsWith("/qr/confirm/")
      ? window.location.pathname
      : "/qr/scan",
  };

  return paths[route];
}

export function apiMessage(error: unknown, context: "register" | "login" | "session" | "logout") {
  if (!(error instanceof ApiError)) return "Não foi possível concluir. Tente novamente.";
  if (error.status === 0 || error.status >= 500) return "O serviço está indisponível agora. Aguarde um momento e tente novamente.";
  if (error.status === 429) return "Muitas tentativas em pouco tempo. Aguarde antes de tentar novamente.";
  if (context === "login" && error.status === 401) return "E-mail ou senha não conferem. Revise os dados e tente novamente.";
  if (context === "register" && error.status === 409) return "Não foi possível criar a conta com esses dados. Tente entrar ou use outro e-mail.";
  if (context === "register" && error.status === 400) return "Revise o e-mail e use uma senha com pelo menos 15 caracteres.";
  if ((context === "session" || context === "logout") && error.status === 401) return "Sua sessão terminou. Entre novamente para continuar.";
  return "Não foi possível concluir. Revise os dados e tente novamente.";
}

export function App() {
  const [route, setRoute] = useState<Route>(() => routeFromPath(window.location.pathname));
  const [session, setSession] = useState<SessionState>({ status: "loading" });
  const [qrReady, setQrReady] = useState(false);
  const [qrChallengeId, setQrChallengeId] = useState(() => window.location.pathname.split("/qr/confirm/")[1] ?? "");

  useEffect(() => {
    const onPopState = () => setRoute(routeFromPath(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (window.location.pathname !== "/qr/scan") return;
    const params = new URLSearchParams(window.location.hash.slice(1));
    const token = params.get("token");
    window.history.replaceState({}, "", "/qr/scan");
    if (!token) return;
    qrApi.bootstrap(token).then(() => setQrReady(true)).catch(() => setQrReady(false));
  }, []);

  useEffect(() => {
    authApi.currentSession()
      .then((value) => setSession({ status: "authenticated", value }))
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 401) setSession({ status: "anonymous" });
        else setSession({ status: "anonymous", notice: apiMessage(error, "session") });
      });
  }, []);

  function navigate(nextRoute: Route) {
    const path = pathForRoute(nextRoute);
    if (window.location.pathname !== path) window.history.pushState({}, "", path);
    setRoute(nextRoute);
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  const activeRoute = route === "account" && session.status !== "authenticated" ? "login" : route;

  async function continueQrScan() {
    const scanned = await qrApi.scan();
    setQrChallengeId(scanned.challenge_id);
    window.history.replaceState({}, "", `/qr/confirm/${scanned.challenge_id}`);
    setRoute("qrConfirm");
  }

  return (
    <div className="page-shell">
      <SiteHeader route={activeRoute} session={session} navigate={navigate} />
      <main id="conteudo" tabIndex={-1}>
        {session.status === "loading" && activeRoute !== "home" ? (
          <LoadingSurface />
        ) : activeRoute === "home" ? (
          <Landing navigate={navigate} session={session} />
        ) : activeRoute === "register" ? (
          <RegisterSurface navigate={navigate} />
        ) : activeRoute === "login" ? (
          <LoginSurface session={session} setSession={setSession} navigate={navigate} />
        ) : activeRoute === "qrDesktop" ? (
          <QrDesktopSurface setSession={setSession} navigate={navigate} />
        ) : activeRoute === "qrCamera" ? (
          <QrCameraSurface />
        ) : activeRoute === "qrScan" ? (
          session.status === "authenticated" ? <QrScanSurface ready={qrReady} onContinue={continueQrScan} /> : <LoginSurface session={session} setSession={setSession} navigate={navigate} onAuthenticated={continueQrScan} qrContext />
        ) : activeRoute === "qrConfirm" && session.status === "authenticated" ? (
          <QrConfirmSurface challengeId={qrChallengeId} navigate={navigate} />
        ) : session.status === "authenticated" ? (
          <AccountSurface session={session.value} setSession={setSession} navigate={navigate} />
        ) : null}
      </main>
    </div>
  );
}

function SiteHeader({ route, session, navigate }: { route: Route; session: SessionState; navigate: (route: Route) => void }) {
  const link = (target: Route, label: string) => (
    <a href={pathForRoute(target)} className={route === target ? "active" : undefined} aria-current={route === target ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate(target); }}>{label}</a>
  );

  return (
    <header className="side-rail">
      <a className="brand" href="/" aria-label="Sentinel: apresentação" onClick={(event) => { event.preventDefault(); navigate("home"); }}>
        <span className="registration-mark" aria-hidden="true"><i /></span><span>Sentinel</span>
      </a>
      <nav aria-label="Navegação principal">
        {link("home", "Apresentação")}
        {link("register", "Criar conta")}
        {link("login", "Entrar")}
        {link("qrDesktop", "Entrar por QR")}
        {session.status === "authenticated" && link("account", "Sua sessão")}
      </nav>
      <p className="rail-copy">Autenticação entre dispositivos com aprovação explícita e estado verificável.</p>
      <button className="rail-link" type="button" onClick={() => navigate(session.status === "authenticated" ? "account" : "register")}>
        {session.status === "authenticated" ? "Ver sessão" : "Criar uma conta"}<span aria-hidden="true">→</span>
      </button>
      <div className="rail-status"><span aria-hidden="true" /> {session.status === "authenticated" ? "Sessão ativa" : "Projeto em evolução"}</div>
    </header>
  );
}

function Landing({ navigate, session }: { navigate: (route: Route) => void; session: SessionState }) {
  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <RegistrationTarget />
        <div className="hero-copy">
          <h1 id="hero-title">Aprovação<br />explícita.<br /><em>Estado<br />verificável.</em></h1>
          <div className="hero-rule" />
          <h2>Senha no celular.<br />QR no desktop.</h2>
          <p>O Sentinel cria um pedido temporário, exige comparação ativa do código e conclui a sessão pelo estado persistido — mesmo quando o WebSocket falha.</p>
          <button className="primary-action" type="button" onClick={() => navigate(session.status === "authenticated" ? "account" : "register")}>
            {session.status === "authenticated" ? "Ver sessão ativa" : "Criar conta"}<span aria-hidden="true">→</span>
          </button>
          <div className="state-line" aria-label="Estados planejados do protocolo entre dispositivos">
            {states.map((state, index) => <span key={state} className={`state state-${index}`}>{state}{index < states.length - 1 && <i aria-hidden="true">→</i>}</span>)}
          </div>
        </div>
      </section>
      <section className="protocol" id="protocolo" aria-labelledby="protocol-title">
        <div className="section-heading"><h2 id="protocol-title">Quatro transições.<br />Nenhum salto implícito.</h2><p>O canal em tempo real informa. O estado persistido decide.</p></div>
        <ol className="stage-list">{stages.map((stage, index) => <li key={stage.title}><span>{String(index + 1).padStart(2, "0")}</span><h3>{stage.title}</h3><p>{stage.body}</p></li>)}</ol>
      </section>
      <section className="architecture" id="arquitetura" aria-labelledby="architecture-title">
        <div className="architecture-copy"><h2 id="architecture-title">Tempo real sem ponto único de falha.</h2><p>O WebSocket acelerará a percepção. Se ele cair, o desktop consultará o estado por polling e concluirá a troca com o mesmo segredo temporário.</p></div>
        <dl><div><dt>Experiência</dt><dd>WebSocket + snapshot</dd></div><div><dt>Continuidade</dt><dd>Polling autenticado</dd></div><div><dt>Verdade</dt><dd>PostgreSQL + transação</dd></div></dl>
      </section>
      <section className="build-status" id="estagio" aria-labelledby="status-title">
        <div><h2 id="status-title">O que existe hoje</h2><p>Cadastro, senha, sessão HTTP, challenge temporário, bootstrap pelo fragmento, number matching, aprovação móvel, WebSocket e fallback por polling.</p></div>
        <div><h2>Limite explícito</h2><p>Number matching reduz aprovações acidentais, mas não impede relay ou phishing em tempo real. Passkeys e sinais de proximidade permanecem evoluções futuras.</p></div>
        <p className="honesty-note">Projeto educacional e de portfólio. Ainda não indicado para autenticação em produção.</p>
      </section>
    </>
  );
}

function RegistrationTarget() {
  return <div className="target" aria-label="Desktop, estado persistido e celular convergem para formar uma sessão"><div className="pass pass-desktop"><span>Desktop</span></div><div className="pass pass-state"><span>Estado persistido</span></div><div className="pass pass-mobile"><span>Celular</span></div><div className="target-rings" aria-hidden="true"><i /><i /></div><strong>Sessão</strong><span className="crosshair crosshair-top" aria-hidden="true" /><span className="crosshair crosshair-bottom" aria-hidden="true" /></div>;
}

function AuthFrame({ title, intro, children, aside }: { title: string; intro: string; children: React.ReactNode; aside: React.ReactNode }) {
  return <section className="auth-surface" aria-labelledby="auth-title"><div className="auth-form-column"><h1 id="auth-title">{title}</h1><p className="auth-intro">{intro}</p>{children}</div><aside className="auth-aside">{aside}<div className="auth-registration" aria-hidden="true"><span /><span /><span /></div></aside></section>;
}

function RegisterSurface({ navigate }: { navigate: (route: Route) => void }) {
  const [status, setStatus] = useState<"idle" | "submitting" | "success">("idle");
  const [message, setMessage] = useState("");

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("submitting");
    setMessage("");
    const form = new FormData(event.currentTarget);

    try {
      await authApi.register(String(form.get("email")), String(form.get("password")));
      setStatus("success");
    } catch (error) {
      setStatus("idle");
      setMessage(apiMessage(error, "register"));
    }
  }

  return <AuthFrame title="Criar conta" intro="Este cadastro cria sua identidade, mas não inicia uma sessão. Depois da confirmação do servidor, você poderá entrar." aside={<><h2>Um registro real.</h2><p>A senha é enviada somente ao backend por HTTPS em produção. O navegador recebe a sessão apenas no login, em cookie HTTP inacessível ao JavaScript.</p></>}>
    {status === "success" ? <StatusMessage kind="success" title="Conta criada pelo servidor."><p>Agora entre com o mesmo e-mail e senha para abrir sua sessão.</p><button className="primary-action" type="button" onClick={() => navigate("login")}>Ir para entrada <span aria-hidden="true">→</span></button></StatusMessage> : <AuthForm action="Criar conta" autocomplete="new-password" submitting={status === "submitting"} message={message} onSubmit={submit} />}
    <p className="auth-switch">Já tem uma conta? <button type="button" onClick={() => navigate("login")}>Entrar</button></p>
  </AuthFrame>;
}

function LoginSurface({ session, setSession, navigate, onAuthenticated, qrContext = false }: { session: SessionState; setSession: (value: SessionState) => void; navigate: (route: Route) => void; onAuthenticated?: () => Promise<void>; qrContext?: boolean }) {
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState(session.status === "anonymous" ? session.notice ?? "" : "");

  if (session.status === "authenticated") return <AuthFrame title="Sessão já ativa" intro={`Você entrou como ${session.value.user.email}.`} aside={<><h2>Registro alinhado.</h2><p>O backend confirmou a sessão apresentada pelo cookie seguro.</p></>}><button className="primary-action" type="button" onClick={() => navigate("account")}>Ver sua sessão <span aria-hidden="true">→</span></button></AuthFrame>;

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setMessage("");
    const form = new FormData(event.currentTarget);

    try {
      const value = await authApi.login(String(form.get("email")), String(form.get("password")));
      setSession({ status: "authenticated", value });
      if (onAuthenticated) {
        await onAuthenticated();
      } else {
        navigate("account");
      }
    } catch (error) {
      setSubmitting(false);
      setMessage(apiMessage(error, "login"));
    }
  }

  return <AuthFrame title={qrContext ? "Entre para confirmar" : "Entrar"} intro={qrContext ? "O segredo do QR já foi convertido em uma continuação HttpOnly. Entre para vincular este pedido à sessão móvel exata." : "O backend valida as credenciais e só então abre a sessão. E-mail e senha incorretos recebem a mesma resposta."} aside={<><h2>O servidor decide.</h2><p>Nenhum token de sessão é salvo no JavaScript ou no armazenamento local. Recarregar a página consulta novamente o cookie HTTP.</p></>}><AuthForm action="Entrar" autocomplete="current-password" submitting={submitting} message={message} onSubmit={submit} /><p className="auth-switch">Ainda não tem conta? <button type="button" onClick={() => navigate("register")}>Criar conta</button></p></AuthFrame>;
}

function AuthForm({ action, autocomplete, submitting, message, onSubmit }: { action: string; autocomplete: "new-password" | "current-password"; submitting: boolean; message: string; onSubmit: (event: React.FormEvent<HTMLFormElement>) => void }) {
  return <form className={`auth-form ${message ? "is-misaligned" : ""}`} onSubmit={onSubmit} aria-busy={submitting}>
    {message && <StatusMessage kind="error" title={message} />}
    <div className="field"><label htmlFor="email">E-mail</label><input id="email" name="email" type="email" autoComplete="email" inputMode="email" maxLength={254} required disabled={submitting} /></div>
    <div className="field"><label htmlFor="password">Senha</label><input id="password" name="password" type="password" autoComplete={autocomplete} minLength={15} maxLength={1024} required aria-describedby="password-help" disabled={submitting} /><p id="password-help">Use pelo menos 15 caracteres.</p></div>
    <button className="submit-action" type="submit" disabled={submitting}>{submitting ? "Aguardando o servidor…" : action}<span aria-hidden="true">→</span></button>
  </form>;
}

function AccountSurface({ session, setSession, navigate }: { session: SessionResponse; setSession: (value: SessionState) => void; navigate: (route: Route) => void }) {
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  async function logout() {
    setSubmitting(true);
    setMessage("");

    try {
      await authApi.logout();
      setSession({ status: "anonymous" });
      navigate("login");
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        setSession({ status: "anonymous", notice: apiMessage(error, "logout") });
        navigate("login");
        return;
      }

      setSubmitting(false);
      setMessage(apiMessage(error, "logout"));
    }
  }
  return <section className="account-surface" aria-labelledby="account-title"><div className="account-heading"><h1 id="account-title">Sessão em registro.</h1><p>Identidade confirmada pelo backend. O cookie de sessão continua fora do alcance do JavaScript.</p></div>{message && <StatusMessage kind="error" title={message} />}<dl className="session-record"><div><dt>Identidade</dt><dd>{session.user.email}</dd></div><div><dt>Sessão</dt><dd>{session.session.id}</dd></div><div><dt>Expiração por inatividade</dt><dd>{new Date(session.session.idle_expires_at).toLocaleString("pt-BR")}</dd></div><div><dt>Limite absoluto</dt><dd>{new Date(session.session.absolute_expires_at).toLocaleString("pt-BR")}</dd></div></dl><div className="session-actions"><button className="submit-action" type="button" onClick={() => navigate("qrCamera")}>Escanear QR do desktop <span aria-hidden="true">→</span></button><button className="danger-action" type="button" disabled={submitting} onClick={logout}>{submitting ? "Encerrando no servidor…" : "Encerrar sessão"}</button><p>O logout revoga a sessão e cancela imediatamente pedidos QR vinculados a ela.</p></div></section>;
}

function QrDesktopSurface({ setSession, navigate }: { setSession: (value: SessionState) => void; navigate: (route: Route) => void }) {
  const [challenge, setChallenge] = useState<QrChallengeCreated | null>(null);
  const [snapshot, setSnapshot] = useState<QrSnapshot | null>(null);
  const [qrImage, setQrImage] = useState("");
  const [channel, setChannel] = useState<"connecting" | "websocket" | "polling">("connecting");
  const [message, setMessage] = useState("");
  const exchangeStarted = useRef(false);

  async function start() {
    setMessage("");
    setSnapshot(null);
    exchangeStarted.current = false;

    try {
      setChallenge(await qrApi.create());
    } catch {
      setMessage("Não foi possível criar o pedido. Aguarde e tente novamente.");
    }
  }
  async function restart() {
    if (challenge) await qrApi.cancel(challenge.challenge_id, challenge.subscription_token).catch(() => undefined);
    await start();
  }

  useEffect(() => {
    if (!challenge) return;
    QRCode.toDataURL(challenge.qr_payload, { width: 360, margin: 2, color: { dark: "#182e29", light: "#f4efe3" } }).then(setQrImage);
  }, [challenge]);

  useEffect(() => {
    if (!challenge) return;
    let active = true;
    let socket: WebSocket | null = null;
    let pollDelay = challenge.poll_after_ms;
    let pollTimer = 0;

    const poll = async () => {
      if (!active) return;

      try {
        setSnapshot(await qrApi.status(challenge.challenge_id, challenge.subscription_token));
      } catch {
        // Polling é apenas um canal de atualização; a próxima consulta recupera falhas breves.
      }

      pollDelay = Math.min(Math.round(pollDelay * 1.35), 5000);
      pollTimer = window.setTimeout(poll, pollDelay);
    };

    const beginPolling = () => {
      if (!active) return;
      setChannel("polling");
      window.clearTimeout(pollTimer);
      void poll();
    };

    try {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(`${protocol}//${window.location.host}/v1/qr-login/ws`);
      socket.addEventListener("open", () => {
        setChannel("websocket");
        socket?.send(JSON.stringify({
          type: "subscribe",
          challenge_id: challenge.challenge_id,
          subscription_token: challenge.subscription_token,
          last_seen_version: null,
        }));
      });
      socket.addEventListener("message", (event) => {
        const value = JSON.parse(String(event.data)) as { type: string; challenge_id: string; status: QrSnapshot["status"]; version: number; qr_expires_at: string; approval_expires_at: string | null };
        if (value.type === "qr.snapshot") setSnapshot({ challenge_id: value.challenge_id, status: value.status, lock_version: value.version, qr_expires_at: value.qr_expires_at, approval_expires_at: value.approval_expires_at });
      });
      socket.addEventListener("close", beginPolling);
      socket.addEventListener("error", beginPolling);
    } catch {
      beginPolling();
    }
    const safetyTimer = window.setTimeout(beginPolling, 4000);
    return () => { active = false; window.clearTimeout(safetyTimer); window.clearTimeout(pollTimer); socket?.close(); };
  }, [challenge]);

  useEffect(() => {
    if (!challenge || snapshot?.status !== "APPROVED" || exchangeStarted.current) return;
    exchangeStarted.current = true;
    qrApi.exchange(challenge.challenge_id, challenge.subscription_token)
      .then(() => authApi.currentSession())
      .then((value) => {
        setSession({ status: "authenticated", value });
        setSnapshot((current) => current ? { ...current, status: "EXCHANGED" } : current);
      })
      .catch(() => {
        exchangeStarted.current = false;
        setMessage("A aprovação chegou, mas a troca não concluiu. O Sentinel tentará pelo estado persistido.");
      });
  }, [challenge, snapshot, setSession]);

  return <section className="qr-workspace" aria-labelledby="qr-desktop-title">
    <div className="qr-workspace-heading"><h1 id="qr-desktop-title">Abra uma sessão<br /><em>com o celular.</em></h1><p>O QR inicia o pedido. O código confirma que os dois dispositivos observam a mesma solicitação.</p></div>
    {!challenge ? <div className="qr-start"><div className="registration-orbit" aria-hidden="true"><i /><i /><strong>QR</strong></div><button className="primary-action" type="button" onClick={start}>Criar pedido temporário <span aria-hidden="true">→</span></button>{message && <StatusMessage kind="error" title={message} />}</div> : <div className="qr-desktop-grid">
      <div className="qr-print">{qrImage && <img src={qrImage} alt="QR Code para abrir este pedido no celular" />}<span>Expira {new Date(challenge.qr_expires_at).toLocaleTimeString("pt-BR")}</span></div>
      <div className="qr-verification"><p>Compare no celular</p><strong aria-label={`Código ${challenge.verification_code.split("").join(" ")}`}>{challenge.verification_code}</strong><dl><div><dt>Estado</dt><dd>{snapshot?.status ?? "CREATED"}</dd></div><div><dt>Canal</dt><dd>{channel === "websocket" ? "WebSocket" : channel === "polling" ? "Polling seguro" : "Conectando"}</dd></div></dl>{snapshot?.status === "EXCHANGED" ? <button className="primary-action" type="button" onClick={() => navigate("account")}>Ver nova sessão <span aria-hidden="true">→</span></button> : <button className="rail-link" type="button" onClick={restart}>Cancelar e criar outro</button>}{message && <StatusMessage kind="error" title={message} />}</div>
    </div>}
  </section>;
}

function QrScanSurface({ ready, onContinue }: { ready: boolean; onContinue: () => Promise<void> }) {
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  async function proceed() {
    setSubmitting(true);
    setMessage("");

    try {
      await onContinue();
    } catch {
      setSubmitting(false);
      setMessage("A continuação expirou ou já foi usada. Escaneie o QR novamente.");
    }
  }
  return <section className="qr-mobile-gate" aria-labelledby="qr-scan-title"><div className="mobile-registration" aria-hidden="true"><i /><i /></div><h1 id="qr-scan-title">Pedido capturado.</h1><p>{ready ? "O token do fragmento já saiu da URL e foi convertido em um cookie HttpOnly temporário." : "Nenhuma continuação válida foi encontrada. Abra novamente o QR exibido no desktop."}</p>{message && <StatusMessage kind="error" title={message} />}<button className="submit-action" type="button" disabled={!ready || submitting} onClick={proceed}>{submitting ? "Vinculando à sessão…" : "Continuar neste celular"}<span aria-hidden="true">→</span></button></section>;
}

function QrConfirmSurface({ challengeId, navigate }: { challengeId: string; navigate: (route: Route) => void }) {
  const [details, setDetails] = useState<QrDetails | null>(null);
  const [code, setCode] = useState("");
  const [message, setMessage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    if (!challengeId) return;

    qrApi
      .details(challengeId)
      .then(setDetails)
      .catch(() => setMessage("Este pedido não pertence a esta sessão ou já terminou."));
  }, [challengeId]);

  async function verify(event: React.FormEvent) {
    event.preventDefault();
    if (!details) return;

    setSubmitting(true);
    setMessage("");

    try {
      await qrApi.verifyCode(challengeId, code, details.lock_version);
      setDetails(await qrApi.details(challengeId));
    } catch {
      setMessage("Código incorreto. Confira o desktop; após cinco tentativas o pedido é cancelado.");
    } finally {
      setSubmitting(false);
    }
  }

  async function decide(decision: "approve" | "reject") {
    if (!details) return;

    setSubmitting(true);
    setMessage("");

    try {
      await qrApi.decide(challengeId, decision, details.lock_version);
      navigate("account");
    } catch {
      setSubmitting(false);
      setMessage("O estado mudou antes da sua decisão. Reabra o pedido para conferir o resultado.");
    }
  }
  return <section className="qr-confirm" aria-labelledby="qr-confirm-title"><div className="qr-confirm-copy"><h1 id="qr-confirm-title">É este desktop?</h1><p>Não aprove QR ou código recebido por mensagem. Number matching reduz enganos, mas não impede phishing com relay em tempo real.</p></div>{message && <StatusMessage kind="error" title={message} />}{details && <div className="device-record"><dl><div><dt>Navegador</dt><dd>{details.requested_ua_summary ?? "Não informado"}</dd></div><div><dt>Rede aproximada</dt><dd>{details.requested_ip ?? "Não informada"}</dd></div><div><dt>Solicitado</dt><dd>{new Date(details.created_at).toLocaleString("pt-BR")}</dd></div></dl>{!details.code_verified ? <form onSubmit={verify} className="code-form"><label htmlFor="verification-code">Código de quatro dígitos do desktop</label><input id="verification-code" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 4))} inputMode="numeric" autoComplete="one-time-code" pattern="\d{4}" required /><button className="submit-action" disabled={submitting || code.length !== 4}>Comparar código <span aria-hidden="true">→</span></button></form> : <div className="decision-actions"><button className="submit-action" type="button" disabled={submitting} onClick={() => decide("approve")}>Aprovar este desktop <span aria-hidden="true">→</span></button><button className="danger-action" type="button" disabled={submitting} onClick={() => decide("reject")}>Recusar pedido</button></div>}</div>}</section>;
}

function QrCameraSurface() {
  const video = useRef<HTMLVideoElement>(null);
  const [message, setMessage] = useState(() => (
    "BarcodeDetector" in window
      ? "Solicite acesso à câmera para ler o QR do desktop."
      : "Este navegador não oferece leitura nativa. Use a câmera do sistema para abrir o QR."
  ));
  useEffect(() => {
    let stream: MediaStream | null = null;
    let timer = 0;
    let active = true;
    const Detector = (window as unknown as { BarcodeDetector?: new (options: { formats: string[] }) => { detect(source: CanvasImageSource): Promise<Array<{ rawValue: string }>> } }).BarcodeDetector;

    if (!Detector) {
      return;
    }

    const detector = new Detector({ formats: ["qr_code"] });

    const inspectFrame = async () => {
      if (!active || !video.current) return;

      try {
        const [result] = await detector.detect(video.current);
        if (result?.rawValue.startsWith(window.location.origin)) {
          window.location.assign(result.rawValue);
          return;
        }
      } catch {
        // O detector pode falhar enquanto o primeiro quadro da câmera ainda não está pronto.
      }

      timer = window.setTimeout(inspectFrame, 250);
    };

    navigator.mediaDevices
      .getUserMedia({ video: { facingMode: "environment" } })
      .then((cameraStream) => {
        stream = cameraStream;
        if (video.current) {
          video.current.srcObject = cameraStream;
          void video.current.play();
        }
        void inspectFrame();
      })
      .catch(() => {
        setMessage("A câmera não pôde ser aberta. Revise a permissão ou use a câmera do sistema.");
      });

    return () => {
      active = false;
      window.clearTimeout(timer);
      stream?.getTracks().forEach((track) => track.stop());
    };
  }, []);
  return <section className="qr-camera" aria-labelledby="camera-title"><h1 id="camera-title">Aponte para o QR.</h1><div className="camera-frame"><video ref={video} playsInline muted aria-label="Prévia da câmera" /><i aria-hidden="true" /></div><p role="status">{message}</p></section>;
}

function StatusMessage({ kind, title, children }: { kind: "error" | "success"; title: string; children?: React.ReactNode }) {
  return <div className={`status-message status-${kind}`} role={kind === "error" ? "alert" : "status"}><strong>{title}</strong>{children}</div>;
}

function LoadingSurface() {
  return <section className="loading-surface" aria-live="polite" aria-busy="true"><span className="loading-registration" aria-hidden="true" /><h1>Verificando sessão…</h1><p>O Sentinel está consultando a autoridade do backend.</p></section>;
}

const root = document.getElementById("root");
if (root) createRoot(root).render(<StrictMode><App /></StrictMode>);
