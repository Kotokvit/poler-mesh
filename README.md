# poler-mesh

**Единый MCP-диспетчер POLER-сети: один токен агента → вся экосистема.**

poler-mesh поднимает узлы сети (poler-git, poler-engine, будущие почта/диск)
как дочерние процессы, объединяет их MCP-инструменты в один `tools/list`
и маршрутизует `tools/call` нужному узлу. Агент видит ОДИН сервер с ОДНИМ
токеном — и получает гит, блокноты, поиск и всё, что подключат дальше.

```
                    ┌─────────────────────────────────────┐
  агент ──token──▶  │  poler-mesh                         │
  (CLI/HTTP)        │  tools/list = union всех узлов      │
                    │  tools/call → маршрут к узлу        │
                    └───────┬──────────┬──────────┬───────┘
                       stdio│      stdio│      stdio│
                    ┌───────▼──┐ ┌─────▼────┐ ┌───▼──────┐
                    │poler-git │ │poler-    │ │ почта/   │
                    │(весь гит)│ │engine    │ │ диск ... │
                    └──────────┘ │(NLM,web) │ └──────────┘
                                 └──────────┘
```

Почему так (уроки p3-agent-cell): между хабом и узлами — пайпы ОС,
ноль открытых портов, ноль git-коммитов как транспорта, ноль общих
симметричных секретов. PAT провайдеров остаются внутри своих узлов.
Наружу — один `POLER_MESH_TOKEN`.

## Быстрый старт

```bash
poler-mesh init              # создать ~/.config/poler-mesh/mesh.toml
poler-mesh --nodes           # диагностика: поднять узлы, показать инструменты

# хаб как stdio-узел (для вызова из другого CLI):
poler-mesh --mcp-stdio

# хаб как HTTP-сервер для агента (через туннель):
poler-mesh --mcp-http 127.0.0.1:8770 --mcp-token <секрет>
# или токен из env:
POLER_MESH_TOKEN=секрет poler-mesh --mcp-http
```

Без `--config` хаб ищет `~/.config/poler-mesh/mesh.toml`; если файла нет —
честный автопоиск `poler-git`/`poler-engine` в PATH (в диагнозе видно,
что реально найдено).

## mesh.toml

```toml
[[node]]
id = "git"
cmd = "poler-git"
args = ["--mcp-stdio"]

[[node]]
id = "engine"
cmd = "poler-engine"
args = ["--mcp"]

# Новый узел — тем же паттерном (любой язык, ~100 строк):
# [[node]]
# id = "mail"
# cmd = "poler-mail"
# args = ["--mcp-stdio"]
```

## Как это работает

1. **Спавн**: каждый узел запускается как процесс с piped stdin/stdout
   (stderr наследуется — логи узлов видны в консоли хаба).
2. **Рукопожатие**: `initialize` + `notifications/initialized` (MCP,
   line-delimited JSON-RPC 2.0 — общий стандарт POLER).
3. **Реестр**: `tools/list` каждого узла → карта «имя → узел».
   Конфликт имён решает первый узел; конфликт репортится в stderr.
   Каждый инструмент помечается `_mesh_node` — видно происхождение.
4. **Маршрутизация**: `tools/call` уходит узлу-хозяину имени;
   ответ возвращается агенту как есть. Неизвестное имя — честный
   `isError` со списком доступных.
5. **Один токен**: HTTP-режим проверяет `Authorization: Bearer …`;
   токен — `--mcp-token` или env `POLER_MESH_TOKEN`, без него
   генерируется и печатается при старте.

## Как написать узел сетки

Любая программа, которая:
- читает line-delimited JSON-RPC 2.0 из stdin, пишет в stdout;
- отвечает на `initialize` (serverInfo), `tools/list`, `tools/call`;
- логирует в stderr (не stdout!).

Готовый шаблон на 100 строк: `poler-mesh --mock-node demo`
(исходник — `src/mock.rs`). Именно так тестируется сама сетка.

## HTTP API

- `GET /health` — статус без авторизации (проверка туннеля)
- `POST /` или `POST /mcp` — JSON-RPC 2.0 c `Authorization: Bearer <token>`
- лимиты: 16 соединений, тело ≤ 8 МБ, idle 65 с

## Тесты

```bash
cargo test                # 27 тестов: 22 unit + 5 integration
```

Integration-тесты поднимают полную сетку на мок-узлах (сам бинарник
в двух ролях): агрегация двух узлов, маршрутизация, конфликты имён,
HTTP с токеном и 401 без него. Живой тест реальной сетки —
`scripts/mesh_live_test.py` (poler-git + мок, реальные вызовы GitHub).

## Известные ограничения v0.1

- один JSON-RPC вызов на HTTP-запрос (batch — в v0.2)
- ресурсы/prompts MCP не пробрасываются (только tools)
- висящий узел блокирует хаб (таймауты запросов — в v0.2)
- `notifications/tools/list_changed` от узлов пока игнорируются

## Лицензия

MIT OR Apache-2.0
