<div align="center">

<img src="assets/banner.svg" alt="devin-redact" width="100%"/>

<a href="https://github.com/Icaro0310/devin-redact/actions/workflows/ci.yml"><img src="https://github.com/Icaro0310/devin-redact/actions/workflows/ci.yml/badge.svg" alt="ci"/></a>


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

# SARIF 2.1.0 para ingestão em CI / code-scanning (nunca contém o segredo)
devin-redact scan sessions.db --format sarif > scan.sarif

# Redact em dry-run — mostra exatamente o que mudaria, não modifica nada
devin-redact redact sessions.db

# Redact in-place (flag longa de propósito; grava backups .bak primeiro)
devin-redact redact sessions.db --apply --i-know-this-is-irreversible

# Gate de publicação: exit 0 só quando CLEAN, senão 1
devin-redact verify sessions.db exports/
devin-redact verify sessions.db --json

# Gate para pipelines (ex.: export do devin-history): imprime só a
# palavra de status; sai 0 em CLEAN/REVIEW, 1 em BLOCKED, 2 em erro
devin-redact gate sessions.db exports/

# Handler de hook SessionEnd: scan read-only da sessions.db padrão,
# uma linha de veredito compacta, exit 0 salvo erro grave
devin-redact sessionend-scan
# → devin-redact: findings=7 publication_status=BLOCKED

# Hook SessionEnd (veredito por sessão): resolve a sessão que acabou,
# examina só as mensagens dela e grava o veredito num ficheiro lateral em
# <data-dir>/redact/<session-id>.json — fail-soft, sai 0 mesmo em SKIPPED
devin-redact session-end                       # resolve a sessão sozinho
echo '{"session_id": "abc"}' | devin-redact session-end
devin-redact session-end --session-id abc --out verdict.json

# Gate de um dir de export do devin-history antes de publicar: vereditos
# por sessão cruzados com os ficheiros laterais do session-end;
# exit 0 só quando CLEAN
devin-redact verify-publish exports/
devin-redact verify-publish exports/ --json
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

`scan --format sarif` emite um log [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
em vez do relatório JSON: um rule descriptor por categoria de deteção, um
result por finding com a sua localização (`region.startLine` para ficheiros
de texto; o localizador `table.column#rowid` do SQLite fica preservado em
`properties.location`), uma mensagem mascarada como `match: aws access key
id` e o fingerprint sha256 como `partialFingerprints` para deduplicação.
Categorias de segredo mapeiam para `level: error`, PII/higiene para
`warning`. O log nunca contém o texto do segredo, por isso é seguro enviá-lo
para dashboards de code-scanning ou arquivá-lo como artefacto de CI.

## Hook SessionEnd

`devin-redact sessionend-scan` é a invocação de `scan` feita para o
dispatcher de hooks do ecossistema (`tools/hooks_dispatch.py` no
`devin-powerups`, que corre handlers registrados em eventos de hook do
Devin). É **somente scan**: read-only, limitado à `sessions.db` padrão
auto-detectada, imprime uma linha de veredito compacta
(`findings=N publication_status=X`) e sai 0 mesmo quando o veredito é
`BLOCKED` — não-zero só em erro grave, para nunca travar o encerramento
da sessão. Entrada de registo para o `hooks.json`:

```json
{
  "SessionEnd": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "devin-redact sessionend-scan",
          "timeout": 30
        }
      ]
    }
  ]
}
```

Vê [`docs/HOOKS.md`](docs/HOOKS.md) para o contrato completo.

`devin-redact session-end` é a variante por sessão: resolve **a sessão
que acabou de terminar** — flag `--session-id` → payload JSON
`{"session_id": …}` no stdin → `DEVIN_SESSION_ID` → a sessão mais
recentemente ativa na `sessions.db` — e examina apenas as linhas dessa
sessão (mensagens, tool-call state, histórico de prompts; a linha de
metadados da tabela `sessions` fica de fora). O veredito é gravado num
**ficheiro lateral** — `<data-dir>/redact/<session-id>.json` por
omissão (`--data-dir`, `DEVIN_REDACT_DATA_DIR` ou `--out` podem
sobrepor; `<data-dir>` é a raiz `devin/` do store resolvido) — nunca
dentro de nenhum store ou transcript do Devin. É fail-soft: uma sessão
irresolúvel produz veredito `SKIPPED` e o comando sai 0 mesmo assim; só
erros de uso saem 2. `sessionend-scan` (a linha de veredito do store
inteiro) e `session-end` (o ficheiro lateral por sessão) complementam-se
— escolhe o formato que o teu hook precisa.

## Gate de publicação para exports

`devin-redact verify-publish <export-dir>` cruza os achados de redaction
com o estado de export do
[`devin-history`](https://github.com/Icaro0310/devin-history) antes de
qualquer publicação. Enumera as sessões exportadas — `index.json`
(`{"sessions": [{"file": …}]}`) ou wikilinks do `index.md` quando
presentes, senão o layout `<YYYY-MM-DD>_<session-id>.{md,json}` —
extrai cada `session_id` (campo JSON, frontmatter da nota ou nome do
ficheiro), examina cada ficheiro exportado em read-only e reporta
vereditos por sessão. Quando existe um ficheiro lateral do `session-end`
para uma sessão exportada (`<verdicts-dir>/<session-id>.json`, por
omissão `<data-dir>/redact`), ele é cruzado também: um veredito de hook
`BLOCKED` ao lado de um export `CLEAN` é sinalizado como warning (o
export foi redigido depois — ou descartou o conteúdo sinalizado) e segura
o veredito geral em `REVIEW`. Entradas do índice apontando para ficheiros
ausentes também são sinalizadas. Exit 0 só quando o veredito geral é
`CLEAN`.

## O que é examinado

Os alvos podem ser ficheiros ou diretórios; diretórios são percorridos
recursivamente. Cada ficheiro é despachado por tipo — detetado por extensão
**ou** por conteúdo:

- **Stores SQLite** (`.db`/`.sqlite`/`.sqlite3`, *ou qualquer ficheiro que
  comece com o magic header `SQLite format 3`*) são abertas read-only e
  todas as colunas de texto de todas as tabelas são examinadas. Isto cobre
  o `sessions.db` do Devin e `User/acp-messages/*.db`, além das stores
  derivadas que herdam texto de sessão: o `graph.db` do
  [`devin-graph`](https://github.com/Icaro0310/devin-graph), o `search.db`
  do [`devin-search`](https://github.com/Icaro0310/devin-search)
  (incluindo o `docs` FTS5) e o `memory.db` do
  [`devin-memory`](https://github.com/Icaro0310/devin-memory). Em dados
  com formato `sessions.db` a camada semântica de tool-calls, a extração
  de `project_name` e a passagem cross-chunk também se aplicam; as outras
  stores recebem o scan genérico de colunas de texto.
- **Ficheiros de texto** — notas `.md` (incluindo um dir de export do
  `devin-history`, cujas notas se chamam `<YYYY-MM-DD>_<session-id>.md`),
  exports `.json`/`.jsonl`, `.env`, logs — são examinados por inteiro; os
  findings trazem número de linha.
- **Ficheiros binários** são ignorados e reportados em `errors`.

Em stores com formato `sessions.db` corre ainda uma **passagem
cross-chunk** limitada: segredos divididos entre dois payloads adjacentes
(metade de uma chave AWS no fim do output de uma tool, o resto no início
da mensagem seguinte) remontam-se quando os payloads são concatenados. A
passagem re-examina concatenações de `tool_call_json`+
`tool_call_update_json` da mesma linha de `tool_call_state`, linhas
adjacentes de `tool_call_state`/`message_nodes` **da mesma sessão** e
partes de streaming dentro de um payload — reportando o achado no rowid
mais antigo com `kind="cross-chunk"`.

O `redact` usa o mesmo dispatch: stores SQLite derivadas também são
regraváveis com `--apply`, com as mesmas garantias de `.bak` + transação +
teste de integridade do `sessions.db`.

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
  Segredos em formatos incomuns ou encodings estranhos vão passar.
  Divisões em chunks só são apanhadas entre payloads adjacentes da mesma
  sessão — um segredo espalhado por linhas não-adjacentes, entre sessões
  ou em três ou mais pedaços continua a escapar. Corre também
  `gitleaks`/`trufflehog` — isto complementa-os, não os substitui.
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
- **Escopo M2.** `scan`, `redact`, `verify`, `gate`, `sessionend-scan`,
  `session-end` e `verify-publish`
  funcionam. Ainda fora: publicação PyPI, skill `/redact`. Achados
  cross-chunk são só deteção — o `redact` mascara correspondências por
  célula e não consegue regravar um segredo remontado em duas metades;
  revê esses achados manualmente.

## Quando usar

- Você está prestes a partilhar ou publicar dados de sessões Devin — um export, um bug report, uma base demo — e precisa de limpar segredos e PII primeiro.
- Você quer um gate pré-publicação: `devin-redact verify` sai com 0 apenas quando o alvo está `CLEAN`, por isso encaixa diretamente em CI — ou `devin-redact gate` quando só segredos devem bloquear (sai 1 em `BLOCKED`, 0 em `CLEAN`/`REVIEW`), que é o que o `devin-history` pode consumir via o campo top-level `publication_status` do relatório.
- Você precisa de redação dentro do próprio `sessions.db`, não só em texto exportado — ele reescreve as células SQLite no lugar.
- Você quer achados que um scanner de regex simples não apanha: um tool call `cat .env` marca o seu output como sensível via `tool_call_state.rawInput` mesmo quando o output não corresponde a nenhum padrão.

## Quando NÃO usar

- Você precisa de garantia de que nenhum segredo sobrevive — scanning por padrões tem falsos negativos; corra `gitleaks`/`trufflehog` em paralelo.
- Você quer impedir que segredos entrem nas transcrições em primeiro lugar — isso é trabalho de política de agente, não de redação.
- Você não pode aceitar uma escrita destrutiva — `--apply` reescreve células no lugar; corra o [`devin-backup`](https://github.com/Icaro0310/devin-backup) primeiro e reveja o dry-run.

## FAQ

**O que é o devin-redact?** Um scanner e redator para os stores de sessões do Devin. `scan` lê `sessions.db` (e ficheiros exportados) em read-only e reporta segredos, emails, caminhos absolutos e nomes de projetos; `redact --apply` mascara os achados no lugar como `<REDACTED:sha256prefix>`; `verify` faz gate de publicação com um exit code.

**É seguro correr o scan contra a minha base de dados viva?** Sim — `scan` abre a base read-only e nunca a modifica. Só `redact --apply` escreve, e cria primeiro um `.bak` irmão dentro de uma única transação com um teste de abertura pós-redação.

**O que significa o veredito de publicação?** `publication_status` é `BLOCKED` quando existe qualquer achado de classe segredo, `REVIEW` quando só existem achados de PII/higiene, e `CLEAN` quando nada foi encontrado. `verify` sai 0 apenas em `CLEAN`. O relatório traz previews mascarados e fingerprints sha256 — nunca o segredo em si.

**Ele apanha todos os segredos?** Não. É um scanner heurístico por padrões mais uma camada semântica para leituras de ficheiros sensíveis — formatos invulgares ou encodings serão perdidos, e segredos divididos em chunks só são apanhados quando caem em payloads adjacentes da mesma sessão. Trate-o como um forte complemento ao `gitleaks`/`trufflehog`, não como substituto.

## Licença

MIT — vê [LICENSE](LICENSE).
