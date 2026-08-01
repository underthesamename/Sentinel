# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + TypeScript + Vite no frontend; Rust + Axum no backend; PostgreSQL como fonte de verdade.

## Users

Pessoas avaliando o Sentinel como projeto educacional e de portfólio, além de futuros usuários que desejem autorizar uma sessão em um computador usando um segundo dispositivo já autenticado.

## Product Purpose

O Sentinel demonstra e, progressivamente, implementa autenticação entre dispositivos por QR Code. O desktop cria uma solicitação temporária; o celular escaneia, compara um código e aprova ou recusa; o desktop conclui a troca por uma sessão HTTP.

## Positioning

O fluxo não depende da entrega de um evento em tempo real: PostgreSQL preserva o estado, WebSocket acelera a percepção e polling mantém a conclusão disponível após falhas de conexão.

## Operating Context

A experiência atravessa desktop e celular. A primeira superfície é uma apresentação funcional do projeto; as superfícies operacionais serão incorporadas à medida que os respectivos endpoints forem implementados.

## Capabilities and Constraints

- O estado atual contém a fundação técnica, health checks, domínio inicial e migração PostgreSQL.
- A interface ainda não deve alegar que cadastro, login ou fluxo QR estão disponíveis.
- Um challenge poderá produzir no máximo uma sessão.
- Estados terminais serão irreversíveis.
- CSRF, rate limiting, revogação e proteção contra replay entram junto com cada funcionalidade.
- A identidade visual está livre para ser estabelecida.

## Brand Commitments

O nome do produto é Sentinel. A comunicação deve ser técnica, clara e sem exagerar resistência a phishing ou maturidade de produção.

## Evidence on Hand

- `docs/Sentinel_Especificacao_Tecnica_v0.2.0.docx`: especificação técnica completa.
- `docs/architecture.md`: resumo da arquitetura.
- Não existem usuários, métricas de produção, clientes ou auditorias independentes; esses elementos não devem ser fabricados.

## Product Principles

- O banco é a fonte de verdade; canais em tempo real são aceleradores.
- Segurança é parte do recurso, não uma etapa posterior.
- Aprovação exige intenção explícita e vínculo com a sessão scanner.
- Falhas de rede devem degradar a experiência, não invalidar o fluxo.
- A interface comunica com precisão o que já existe e o que ainda está planejado.

## Accessibility & Inclusion

A aplicação web será responsiva, navegável por teclado, compatível com redução de movimento e construída com contraste e semântica adequados.
