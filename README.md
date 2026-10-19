# Left 4 Dead 2 - Community Audit Tool

Herramienta de auditoria forense externa, ligera y portatil desarrollada en Rust para jugadores, arbitros y administradores de comunidades competitivas de Left 4 Dead 2 en Windows.

El objetivo principal de esta aplicacion es proveer un mecanismo de revision rapido, transparente y no invasivo que permita verificar la integridad del entorno de juego antes o durante partidas de torneo y torneos comunitarios.

---

## Que hace este ejecutable

El ejecutable `l4d2-audit-tool.exe` realiza un analisis forense en varias capas del sistema operativo y de la memoria del juego:

### 1. Deteccion de Inyectores Activos
* Escanea los procesos en ejecucion en Windows comparandolos contra una lista de herramientas de inyeccion comunmente utilizadas (por ejemplo: Xenos, Cheat Engine, Extreme Injector, GH Injector, Process Hacker, entre otros).
* Si un inyector se encuentra en ejecucion en segundo plano, la herramienta lo marca inmediatamente como inyector activo de alto riesgo.

### 2. Deteccion de Residuos en Prefetch (Historial de Ejecucion)
* Analiza el directorio de Prefetch de Windows (`C:\Windows\Prefetch\`).
* Identifica si en el equipo se han ejecutado previamente ejecutables de cheats conocidos, inyectores o herramientas de manipulacion de memoria, aun si fueron cerrados antes de abrir la auditoria.
* Detecta intentos de manipulacion anti-forense, como el vaciado sospechoso o la desactivacion repentina del servicio de Prefetch.

### 3. Analisis de Memoria en Vivo de Left 4 Dead 2 (`left4dead2.exe`)
* Si el juego esta abierto, inspecciona sus regiones de memoria virtual mediante `VirtualQueryEx`.
* Busca memoria ejecutable privada no respaldada por archivos en disco (`MEM_PRIVATE` con proteccion `PAGE_EXECUTE_READWRITE` o `PAGE_EXECUTE_READ`), patron caracteristico de tecnicas como *Manual Mapping* e inyeccion reflectiva de DLLs.
* Analiza los primeros bytes de las regiones ejecutables no respaldadas buscando firmas de encabezados PE (`MZ` / `PE\0\0`) que delatan DLLs inyectadas ocultas.
* Extrae cadenas de texto de la memoria y busca firmas de software de trampas populares en Source Engine (AIMWARE, FUZION, L4D2HOOK, etc.).
* Diferencia contextualmente buffers legitimately creados por el motor grafico (por ejemplo, buffers JIT de shaders de DirectX 9) para evitar falsos positivos.

### 4. Auditoria de Cuentas de Steam
* Localiza la instalacion de Steam en el Registro de Windows.
* Parsea el archivo `loginusers.vdf` para listar todas las cuentas de Steam que han iniciado sesion en la computadora.
* Verifica en `userdata/<ID>/550` y `localconfig.vdf` si cada cuenta ha jugado a Left 4 Dead 2 y extrae la fecha exacta de su ultima partida, permitiendo detectar cuentas secundarias (*smurfs* o *alts*) utilizadas para evadir sanciones.

### 5. Verificacion del Sistema Operativo
* Comprueba si la herramienta cuenta con privilegios de Administrador (`TOKEN_ELEVATION`).
* Obtiene la fecha original de instalacion de Windows y valida claves `Source OS` de actualizaciones del sistema para evitar confusiones de fechas.

### 6. Motor de Clasificacion y Diagnostico
* Consolida todas las anomalias encontradas y asigna un puntaje de riesgo de 0 a 100 con categorias objetivas:
  * LIMPIO (0 - 14 puntos)
  * INCONCLUSO (15 - 34 puntos)
  * SOSPECHOSO (35 - 59 puntos)
  * ALTA SOSPECHA (60 - 84 puntos)
  * EVIDENCIA FUERTE (85 - 100 puntos)
* El reporte desglosa con precision que fue detectado: inyector activo, residuo en prefetch, inyeccion en memoria o parametros normales.

### 7. Transparencia Total
* La herramienta incluye una pestana de "Vista Previa" donde el jugador puede leer exactamente todo el contenido JSON que compone el informe antes de que sea transmitido.
* Ninguna informacion sensible, contrasenas ni archivos personales son leidos o recopilados.

---

## Como usar la herramienta

### Para Jugadores (Auditados)

1. **Abrir el juego (Recomendado):**
   * Si el administrador o arbitro requiere auditar la sesion en vivo, abre *Left 4 Dead 2* y permanece en el menu principal o dentro de la partida.
   * Si el juego no esta abierto, la herramienta aun realizara la auditoria del sistema, Prefetch y cuentas de Steam.

2. **Ejecutar como Administrador:**
   * Haz clic derecho sobre `l4d2-audit-tool.exe` y selecciona **Ejecutar como administrador**.
   * *Nota:* Los permisos de administrador son necesarios para que Windows permita leer la carpeta `C:\Windows\Prefetch` e inspeccionar la memoria del proceso del juego con permisos de lectura.

3. **Ingresar tu Identificador:**
   * En la parte superior de la ventana encontraras el campo **Tag / Identificador**.
   * Escribe el apodo, tag de Discord o identificador que te haya solicitado el arbitro (por ejemplo: `NickJugador#1234`).

4. **Iniciar la Auditoria:**
   * Presiona el boton **Ejecutar Auditoria Completa**.
   * El analisis tomara entre 1 y 2 segundos.

5. **Revisar los Resultados:**
   * **Veredicto:** Muestra el resumen global, nivel de riesgo y la descripcion precisa de los hallazgos.
   * **L4D2:** Detalla el estado del proceso `left4dead2.exe`, consumo de memoria, regiones sospechosas y modulos cargados.
   * **Cuentas Steam:** Muestra la lista de cuentas que han iniciado sesion en el equipo y su ultima actividad en L4D2.
   * **Forense OS:** Informa sobre el estado de Prefetch y fechas del sistema operativo.
   * **Vista Previa:** Permite revisar el documento JSON completo que resume el peritaje.

6. **Enviar el Reporte a los Administradores:**
   * Si la comunidad te proporciono una URL de Worker configurada, asegurate de que este colocada en la pestana **Servidor / Worker**.
   * Haz clic en **Enviar Reporte al Servidor**.
   * Si el envio es exitoso, veras el mensaje de confirmacion en verde y el reporte se publicara de inmediato en el canal privado de Discord de los administradores.

---

### Para Administradores y Organizadores

#### Arquitectura de Transmision Segura (Cloudflare Worker)

Para proteger la infraestructura de la comunidad:
* El webhook de Discord **nunca se compila ni se almacena dentro del ejecutable del cliente**.
* El cliente se comunica exclusivamente con un **Cloudflare Worker** mediante peticiones HTTPS autenticadas con un token secreto de auditoria (`X-Audit-Token`).
* El Worker recibe el JSON, valida la autenticidad del token y genera un mensaje enriquecido (Embed) directamente en el canal privado de Discord de tu servidor.

#### Pasos para desplegar el Worker:

1. Crea una cuenta gratuita en [Cloudflare](https://dash.cloudflare.com/).
2. Ve a **Compute (Workers) > Workers & Pages > Create application > Create Worker**.
3. Pega el codigo de [`worker/worker.js`](worker/worker.js).
4. Guarda y despliega el Worker.
5. Ve a la pestana **Settings > Variables and Secrets** de tu Worker y anade las siguientes dos variables cifradas (Secrets):
   * `DISCORD_WEBHOOK_URL`: La URL del webhook de tu canal de Discord.
   * `AUDIT_SECRET_TOKEN`: Una contrasena o clave secreta que tu elijas (por ejemplo, una cadena alfanumerica segura).
6. En el cliente `l4d2-audit-tool.exe` (en la pestana *Servidor / Worker* o preconfigurado en el codigo fuente), coloca la URL de tu Worker y el token secreto correspondiente.

Para mas detalles, consulta la guia en [`worker/README.md`](worker/README.md).

---

## Estructura del Repositorio

```
anti-cheat/
├── Cargo.toml               # Dependencias y configuracion del proyecto en Rust
├── Cargo.lock               # Registro de versiones fijadas de dependencias
├── README.md                # Documentacion principal de la herramienta
├── src/
│   ├── main.rs              # Punto de entrada de la aplicacion grafica (eframe / egui)
│   ├── lib.rs               # Exportacion de modulos internos para pruebas
│   ├── models.rs            # Modelos de datos (AuditReport, SteamAccount, ProcessAudit, Anomaly)
│   ├── steam.rs             # Localizacion de Steam en el Registro y parseo de VDF
│   ├── game.rs              # Escaneo de memoria virtual (VirtualQueryEx) y modulos de L4D2
│   ├── forensics.rs         # Auditoria de Prefetch, procesos inyectores y fechas de Windows
│   ├── scoring.rs           # Motor de calculo de riesgo ponderado y diagnostico
│   ├── sender.rs            # Cliente HTTP para envio seguro de reportes hacia el Worker
│   └── ui.rs                # Interfaz grafica de usuario interactiva y pestanas de diagnostico
├── tests/
│   └── audit_test.rs        # Suite de pruebas unitarias y de integracion
└── worker/
    ├── worker.js            # Codigo fuente del Cloudflare Worker Proxy para Discord
    └── README.md            # Guia paso a paso de configuracion del Worker
```

---

## Compilacion desde Codigo Fuente

### Requisitos Previos:
* Windows 10 o Windows 11 (64-bit).
* Rust y Cargo instalados (version 1.80+ recomendada, compatible con toolchain MSVC).
* C++ Build Tools (incluidas en Visual Studio Community o Visual Studio Build Tools).

### Instrucciones de Compilacion:

1. Clonar el repositorio:
   ```bash
   git clone https://github.com/jvliet585/anticheat.git
   cd anticheat
   ```

2. Ejecutar en modo desarrollo:
   ```powershell
   cargo run
   ```

3. Compilar el binario optimizado para distribucion:
   ```powershell
   cargo build --release
   ```
   El binario compilado estara disponible en:
   `target\release\l4d2-audit-tool.exe` (~5.3 MB, totalmente portable, sin dependencias externas).

4. Ejecutar las pruebas automatizadas:
   ```powershell
   cargo test -- --nocapture
   ```

---

## Licencia y Uso Responsable

Esta herramienta esta disenada para la administracion y moderacion comunitaria en torneos y servidores competitivos de Left 4 Dead 2. Respeta la privacidad del usuario limitando las consultas exclusivamente a artefactos relacionados con la ejecucion de procesos, la memoria del juego y la instalacion de Steam.
