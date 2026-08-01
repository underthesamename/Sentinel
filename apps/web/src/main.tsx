import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const states = ["CREATED", "SCANNED", "APPROVED", "EXCHANGED"];

const stages = [
  { title: "Desktop solicita", body: "Cria um challenge temporário e exibe QR Code e código de confirmação." },
  { title: "Celular confirma", body: "Escaneia, compara o código e registra uma decisão explícita do usuário." },
  { title: "Servidor persiste", body: "Valida transições e concorrência no PostgreSQL, a fonte de verdade." },
  { title: "Sessão é trocada", body: "O desktop conclui por HTTP exatamente uma vez, mesmo após perder o WebSocket." }
];

function App() {
  return (
    <div className="page-shell">
      <header className="side-rail">
        <a className="brand" href="#inicio" aria-label="Sentinel — início">
          <span className="registration-mark" aria-hidden="true"><i /></span>
          <span>Sentinel</span>
        </a>
        <nav aria-label="Navegação principal">
          <a className="active" href="#inicio">Visão geral</a>
          <a href="#protocolo">Protocolo</a>
          <a href="#arquitetura">Arquitetura</a>
          <a href="#estagio">Estágio atual</a>
        </nav>
        <p className="rail-copy">Autenticação entre dispositivos com aprovação explícita e estado verificável.</p>
        <a className="rail-link" href="#protocolo">Conhecer o protocolo <span aria-hidden="true">↘</span></a>
        <div className="rail-status"><span aria-hidden="true" /> Fundação técnica</div>
      </header>

      <main id="inicio">
        <section className="hero" aria-labelledby="hero-title">
          <div className="target" aria-label="Desktop, estado persistido e celular convergem para formar uma sessão">
            <div className="pass pass-desktop"><span>Desktop</span></div>
            <div className="pass pass-state"><span>Estado persistido</span></div>
            <div className="pass pass-mobile"><span>Celular</span></div>
            <div className="target-rings" aria-hidden="true"><i /><i /></div>
            <strong>Sessão</strong>
            <span className="crosshair crosshair-top" aria-hidden="true" />
            <span className="crosshair crosshair-bottom" aria-hidden="true" />
          </div>

          <div className="hero-copy">
            <h1 id="hero-title">Aprovação<br />explícita.<br /><em>Estado<br />verificável.</em></h1>
            <div className="hero-rule" />
            <h2>Um challenge.<br />Uma sessão.</h2>
            <p>O Sentinel foi projetado para autorizar uma sessão no computador usando um segundo dispositivo. Quando implementado, o celular registrará a decisão e o desktop poderá recuperar a troca após falhas de conexão.</p>
            <a className="primary-action" href="#protocolo">Entender o fluxo <span aria-hidden="true">→</span></a>
            <div className="state-line" aria-label="Estados do protocolo">
              {states.map((state, index) => (
                <span key={state} className={`state state-${index}`}>{state}{index < states.length - 1 && <i aria-hidden="true">→</i>}</span>
              ))}
            </div>
          </div>
        </section>

        <section className="protocol" id="protocolo" aria-labelledby="protocol-title">
          <div className="section-heading">
            <h2 id="protocol-title">Quatro transições.<br />Nenhum salto implícito.</h2>
            <p>O canal em tempo real informa. O estado persistido decide.</p>
          </div>
          <ol className="stage-list">
            {stages.map((stage, index) => (
              <li key={stage.title}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <h3>{stage.title}</h3>
                <p>{stage.body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="architecture" id="arquitetura" aria-labelledby="architecture-title">
          <div className="architecture-copy">
            <h2 id="architecture-title">Tempo real sem ponto único de falha.</h2>
            <p>O WebSocket acelera a percepção. Se ele cair, o desktop consulta o estado por polling e conclui a troca com o mesmo segredo temporário.</p>
          </div>
          <dl>
            <div><dt>Experiência</dt><dd>WebSocket + snapshot</dd></div>
            <div><dt>Continuidade</dt><dd>Polling autenticado</dd></div>
            <div><dt>Verdade</dt><dd>PostgreSQL + transação</dd></div>
          </dl>
        </section>

        <section className="build-status" id="estagio" aria-labelledby="status-title">
          <div>
            <h2 id="status-title">O que existe hoje</h2>
            <p>Fundação executável, domínio inicial, API de saúde, schema PostgreSQL, documentação e pipeline de build.</p>
          </div>
          <div>
            <h2>Próximo marco</h2>
            <p>Cadastro, login por senha, sessão HTTP, cookies seguros, CSRF e rate limiting.</p>
          </div>
          <p className="honesty-note">Projeto educacional e de portfólio. Ainda não indicado para autenticação em produção.</p>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
