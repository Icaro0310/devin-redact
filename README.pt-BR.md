<div align="center">

<img src="assets/banner.svg" alt="devin-redact" width="100%"/>

</div>

# devin-redact

> **Projeto comunitário não oficial.** Sem afiliação, endosso ou patrocínio da
> Cognition AI. "Devin" é marca registada da Cognition AI.

**[English](README.md)** · Português (BR)

Redação de segredos e PII que entende a semântica de tool calls do Devin —
in-place na `sessions.db`, não só texto plano.

## O problema

Transcripts de agentes acumulam segredos: `cat .env` no output de uma tool,
chaves coladas no chat, tokens dentro de mensagens de erro. Publicar ou
partilhar essas sessões vaza credenciais. Não é hipotético: durante a
auditoria que motivou este projeto, foi encontrado um **código de
pareamento real do Devin CLI** dentro de um prompt no histórico local.

## Trabalho anterior (prior art)

- **geheim** — redige segredos de transcripts do Claude Code antes de
  partilhar.
- **agent-leaks** — audita logs de sessão de agentes (JSONL) à procura de
  credenciais vazadas.
- **AgentLogs** — ferramentas para inspecionar/exportar logs de sessão de
  agentes.

Estas ferramentas operam sobre **ficheiros JSONL** estilo Claude Code /
Codex. Nenhuma lê a `sessions.db` do Devin, e nenhuma sabe que um tool call
`cat .env` e o seu output são o mesmo evento. O `devin-redact` adapta a
ideia; não reinventa a roda.

## O que o torna Devin-native

1. **Lado a lado:** lê *e* vai escrever o store relacional de sessões
   (`sessions.db`, `acp-messages/*.db`) — as ferramentas acima só mastigam
   ficheiros e não distinguem o comando (`rawInput`) do seu output.
2. **Sem Devin:** sem o Devin o extra desaparece — não há `tool_call_state`,
   `message_nodes` nem códigos de pareamento.
3. **Uma frase:** *é o único limpador que entende os comandos que correram e
   limpa a base de dados, não só o texto.*

O `scan` abre a DB em modo read-only, descodifica os payloads
`tool_call_json` / `tool_call_update_json` / `chat_message` e encontra
segredos nos inputs *e* nos outputs das tools. Por cima dos padrões, a
camada semântica lê `tool_call_state.rawInput`: quando o comando tocou um
ficheiro sensível conhecido (`cat .env`, `type credentials.toml`, uma tool
de leitura apontada a `~/.ssh/…`), o seu output é marcado como
`kind="semantic-context"` mesmo quando nenhum padrão corresponde. O
`redact` reescreve essas células in-place — mascaradas como
`<REDACTED:sha256prefix>` — mantendo o JSON válido, dentro de uma única
transação com backup `.bak` obrigatório e teste de abertura pós-redação.

## Instalação

Requer Python ≥ 3.10 e `pipx`. **Windows (PowerShell):** instale `pipx` com `py -m pip install --user pipx`, execute `py -m pipx ensurepath` e reabra o terminal. **Linux (Debian/Ubuntu):** execute `sudo apt install pipx python3-venv` e `pipx ensurepath`; reabra o terminal. Noutras distribuições Linux, instale `pipx` pelo gestor de pacotes.

```bash
pipx install "devin-redact @ git+https://github.com/Icaro0310/devin-redact.git"
```

Para desenvolvimento:

```bash
pip install -e ".[dev]"
pytest
```

## Uso

```bash
# Scan read-only — imprime o relatório JSON (contrato da SPEC §6)
devin-redact scan caminho/para/sessions.db exports/ .env

# Igual, mas também grava o relatório num ficheiro
devin-redact scan sessions.db --report report.json

# Redact em dry-run — mostra exatamente o que mudaria, não modifica nada
devin-redact redact sessions.db

# Redact in-place (flag longa de propósito; grava backups .bak primeiro)
devin-redact redact sessions.db --apply --i-know-this-is-irreversible

# Gate de publicação: exit 0 só quando CLEAN, senão 1
devin-redact verify sessions.db exports/
devin-redact verify sessions.db --json
```

Formato do relatório (determinístico — mesmo input, mesmo output):

```json
{"files_scanned": 4, "secrets": 20, "emails": 3,
 "absolute_paths": 5, "project_names": 1,
 "publication_status": "BLOCKED", "findings": [...]}
```

`publication_status` é `BLOCKED` quando existe qualquer finding da classe
segredos, `REVIEW` quando só há findings de PII/higiene, e `CLEAN` quando
nada foi encontrado. Cada finding traz um `preview` mascarado e um
`fingerprint` (sha256, 16 hex) — o relatório nunca contém o segredo.

Categorias de deteção: API keys (formatos OpenAI/Stripe/AWS/Google/Slack),
bearer tokens e JWTs, tokens GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
`github_pat_`), chaves privadas PEM, assignments estilo `.env` para nomes de
variáveis sensíveis, códigos de pareamento Devin, emails e paths absolutos
de utilizador (`C:\Users\…`, `/home/…`, `/Users/…`).

## Funciona só com o Devin (modo Devin-only)

O `scan` default é somente-leitura e totalmente offline. O `--apply`
reescreve a store SQLite do Devin in-place — grava backups `.bak` antes, e
correr o [`devin-backup`](https://github.com/Icaro0310/devin-backup) antes
disso é a rede de segurança recomendada. A deteção é heurística: revê o
relatório antes de aplicar.

## Suporte de plataformas

Python stdlib puro — comportamento idêntico em Windows, Linux e macOS. O
CI corre a suite em `windows-latest` + `ubuntu-latest`; a base de dados
alvo é sempre um argumento explícito, sem paths específicos de
plataforma.

## Limitações

- **Falsos negativos existem.** É um scanner por padrões, não uma garantia.
  Segredos em formatos incomuns, encodings estranhos ou divididos em chunks
  vão passar. Corre também `gitleaks`/`trufflehog` — isto complementa-os,
  não os substitui.
- **Falsos positivos existem.** O matching de `.env` por palavra-chave pode
  marcar assignments benignos; códigos de pareamento só são marcados com
  contexto explícito.
- **Internals privados.** O schema da `sessions.db` e os formatos JSON
  `chisel`/`acp` não são documentados e podem mudar entre versões do Devin
  CLI. O scanner lê células genericamente para ser resiliente, mas uma
  mudança de schema pode reduzir o recall.
- **Não é preventivo.** Encontra segredos *depois* de aterrarem no
  transcript. Impedir o agente de ler segredos é trabalho de policy, não de
  redação.
- **Redação é destrutiva por desenho.** `--apply` grava sempre um `.bak`
  irmão primeiro e as escritas na DB correm numa transação única com teste
  de abertura pós-redação — mas depois de publicares/partilhares uma árvore
  sem `.bak`, os segredos que lá estavam são a única cópia. Guarda os
  backups em segurança.
- **A camada semântica é heurística.** A tabela de ficheiros sensíveis
  cobre nomes comuns (`.env*`, `credentials*`, `*.pem`, `~/.ssh`, `~/.aws`,
  …); um ficheiro com segredos e nome incomum lido via `cat` não é marcado
  — os padrões continuam a aplicar-se ao output.
- **Escopo M2.** `scan`, `redact` e `verify` funcionam. Ainda fora:
  integração `devin-history`, publicação PyPI, hook `SessionEnd`, skill
  `/redact`.

## Licença

MIT — vê [LICENSE](LICENSE).
