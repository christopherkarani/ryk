<p align="center">
  <a href="https://rykanv.com/">Sitio web</a> ·
  <a href="https://discord.gg/uZn9MDUYKx">Discord</a> ·
  <a href="CONTRIBUTING.md">Contribuir</a> ·
  <a href="SECURITY.md">Seguridad</a>
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ur-pk.md">اردو</a>
</p>

<p align="center">
  <a href="https://github.com/christopherkarani/ryk/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/christopherkarani/ryk/build.yml?label=build" alt="Estado de compilación"></a>
  <a href="https://github.com/christopherkarani/ryk/blob/main/LICENSE"><img src="https://img.shields.io/github/license/christopherkarani/ryk" alt="Licencia Apache 2.0"></a>
  <a href="https://github.com/christopherkarani/ryk"><img src="https://img.shields.io/github/stars/christopherkarani/ryk?style=flat" alt="Estrellas en GitHub"></a>
</p>

# ryk

**Guardrails locales para agentes de programación.**

Ejecuta Claude Code, Codex, Pi, OpenCode, Hermes, OpenClaw o Grok con un único binario local. ryk comprueba comandos, archivos, secretos, red y acciones MCP antes de que lleguen a tu máquina — allow / ask / deny / observe — y conserva la evidencia en disco.

<p align="center">
  <img src="docs/assets/ryk-deny-demo.gif" alt="ryk deniega un comando rm -rf / de OpenCode" width="720">
</p>

<p align="center"><em>El agente intenta <code>rm -rf</code>. ryk lo deniega. La sesión permanece en tu portátil.</em></p>

## Instalar

```sh
curl -fsSL https://rykanv.com/install | sh
```

## Iniciar un agente

```sh
ryk claude    # or: codex | pi | opencode | openclaw | hermes | grok
```

Analiza sesiones anteriores de agentes en busca de comandos riesgosos y exposición de datos similares a secretos:

```sh
ryk scan
```

Si ryk te evita un mal día, [marca el repositorio con una estrella](https://github.com/christopherkarani/ryk) — ayuda a que otros ingenieros lo encuentren.

## Qué obtienes

| | |
| --- | --- |
| Integraciones de host | Alias de lanzamiento para Pi, Hermes, OpenCode, Codex, Claude Code, OpenClaw y Grok. Cursor se admite mediante descubrimiento de host y su shell hook. |
| Sandbox del SO | Sandbox automático del sistema de archivos con Seatbelt en macOS y Landlock en Linux cuando está disponible. Windows no tiene sandbox del SO (solo grado wrapper/hook). |
| Redacción de secretos | Los valores similares a secretos se redactan antes de escribir datos de auditoría y replay. |
| Protección MCP | Las llamadas a herramientas MCP se clasifican localmente, y los servidores stdio compatibles pasan por el proxy protegido de ryk. |
| 86 paquetes de seguridad | Patrones de comandos integrados para operaciones destructivas y sensibles, con paquetes opcionales a nivel de proyecto. |
| Decisiones de política | Decisiones `allow`, `ask`, `deny` y `observe` para acciones locales. |
| Evidencia local | Un dashboard en localhost (incluida una vista Terminal de comandos bloqueados) y comandos replay para sesiones, decisiones y registros de auditoría. |
| Un binario local | El CLI en Zig gestiona lanzamiento, evaluación, comprobaciones de política, adaptadores de host y diagnósticos. |



### Hosts compatibles

| Host | Punto de entrada | Punto de integración |
| --- | --- | --- |
| Pi | `ryk pi` | Bundled extension |
| Hermes | `ryk hermes` | `pre_tool_call` |
| OpenCode | `ryk opencode` | `tool.execute.before` |
| Codex | `ryk codex` | `PreToolUse` |
| Claude Code | `ryk claude` | `PreToolUse` |
| OpenClaw | `ryk openclaw` | `tool.before` |
| Grok | `ryk grok` | `PreToolUse` |
| Cursor | Host discovery y preset `cursor-agent` | `beforeShellExecution` |



## Cómo funciona la política

ryk evalúa cada acción protegida localmente. Las principales superficies de política son:

| Superficie | Ejemplos |
| --- | --- |
| Comandos | Comandos de shell, pipelines, redirecciones e intérpretes |
| Archivos | Archivos del workspace, archivos de control del proyecto y rutas sensibles |
| Entorno | Variables heredadas y acceso a secretos |
| Red | Listas de permitidos de host y conexiones salientes mediadas |
| Herramientas | Llamadas a herramientas MCP y de host mapeadas a efectos |

El modo de política controla la respuesta:

| Modo | Comportamiento |
| --- | --- |
| `observe` | Registra decisiones sin bloquear acciones compatibles |
| `ask` | Pide confirmación para acciones riesgosas cuando el host puede reanudarlas |
| `strict` | Deniega acciones desconocidas o riesgosas salvo que una regla las permita |
| `ci` | Ejecuta comportamiento estricto sin preguntas; `ask` se convierte en deny |

Las reglas de denegación explícitas tienen prioridad. Los paquetes de seguridad clasifican comandos y efectos, pero no conceden permiso por encima de una regla de denegación.

Valida un preset integrado:

```sh
ryk policy check --preset ask
```

Consulta la [referencia de políticas](docs/policy.md) para archivos de política, prioridades y ejemplos.

## Paquetes de seguridad

Los paquetes de seguridad amplían el evaluador de shell con cobertura de comandos enfocada. Paquetes base como `core.*` y `system.disk` están habilitados por defecto.

```sh
ryk packs
ryk packs show core.git
ryk packs enable containers.docker database.postgresql
ryk packs disable containers.docker
```

En un workspace Git, las selecciones de paquetes del proyecto se guardan en `.ryk.toml`. Usa `ryk packs` para scripts y diagnósticos.

Prueba o explica un comando sin ejecutarlo:

```sh
ryk test "git status"
ryk test "rm -rf /" --format json
ryk explain "rm -rf /"
```

## Arquitectura

Los alias de lanzamiento, adaptadores de host, evaluador de shell y motor de políticas comparten una única ruta local de decisión.

<p align="center">
  <img src="docs/images/ryk-architecture.svg" alt="Arquitectura de ryk desde hosts de agentes a través de política local hasta efectos protegidos y evidencia" width="100%">
</p>

1. Un alias de lanzamiento inicia el agente con los valores predeterminados de sesión de ryk.
2. Los adaptadores de host envían eventos de shell y herramientas al evaluador.
3. El evaluador combina reglas de política, coincidencias de paquetes de seguridad y el modo activo.
4. ryk permite, pregunta, observa o deniega la acción.
5. La sesión registra evidencia local para el dashboard y los comandos replay.

## Dashboard

Inicia el dashboard en localhost:

```sh
ryk dashboard
```

Abre [http://127.0.0.1:7742](http://127.0.0.1:7742). El servidor es solo localhost por defecto y usa las rutas existentes de política y CLI de ryk.

Para pruebas de humo y automatización, `--once` atiende una solicitud y luego sale:

```sh
ryk dashboard --once
```

## Límites

ryk es mediación graduada, no un sandbox universal del SO. Es macOS/Linux-first. Las sesiones en Windows se ejecutan a grado wrapper/hook sin sandbox del SO. Binarios de ruta absoluta, herramientas sin shim, tráfico sin proxy y hooks de host que no se disparan pueden quedar fuera de una superficie de aplicación concreta. `ryk doctor` informa de la capacidad de la plataforma; no demuestra que una sesión secundaria se haya adjuntado a un sandbox del SO, y no puede promover Windows a `OS-enforced`. Lee la [matriz de compatibilidad](docs/compatibility.md) y el [modelo de amenazas](docs/threat-model.md) antes de hacer una afirmación más fuerte.

Las compilaciones de release incluyen telemetría de producto opcional: no se recopila ni envía nada a menos que ejecutes `ryk telemetry enable`. Consulta [docs/telemetry.md](docs/telemetry.md) para el contrato exacto de payload.

## Documentación

Empieza por el [índice de documentación](docs/README.md). Las guías más útiles son:

- [Instalación y artefactos de release](docs/install.md)
- [Inicio rápido](docs/quickstart.md)
- [Comandos](docs/commands.md)
- [Política](docs/policy.md)
- [Credenciales y gestión de secretos](docs/credentials.md)
- [MCP](docs/mcp.md)
- [Notas de plataforma](docs/platform-linux.md)
- [Plataforma Windows](docs/platform-windows.md)

## Contribuir

ryk se construye con Zig 0.16.0. Desde un checkout:

```sh
./scripts/zig version
./scripts/compile-fast.sh check
./scripts/zig build test-shell-engine
```

Lee [CONTRIBUTING.md](CONTRIBUTING.md) antes de abrir un pull request. Para problemas de seguridad, usa [SECURITY.md](SECURITY.md).

## Comunidad

- [Sitio web](https://rykanv.com/)
- [Discord](https://discord.gg/uZn9MDUYKx)
- [Issues de GitHub](https://github.com/christopherkarani/ryk/issues)

## Licencia

Apache 2.0. Consulta [LICENSE](LICENSE).
