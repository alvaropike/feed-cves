# Feed de vulnerabilidades (EUVD)

Tabla web con las CVE publicadas recientemente: CVE, nombre, fabricante, CWE, criticidad,
EPSS y fecha. Fuentes: EU Vulnerability Database de ENISA para el listado y la puntuación
CVSS, cve.org para el título oficial y las CWE de cada CVE —con el NVD del NIST de
respaldo para las CWE—, FIRST para la EPSS y los catálogos VulnCheck KEV, CISA KEV y
EU KEV para marcar lo que ya se está explotando.

Opcionalmente avisa por Telegram, y ahí manda **VulnCheck y solo VulnCheck**: solo se avisa
de lo que su catálogo da por explotado, y todo lo que dice el mensaje sale de sus dos
índices. La web enseña los catorce días enteros con todas las fuentes; el grupo, solo lo que
hay que parchear ya. Ver más abajo.

## Por qué no se llama a la API desde el navegador

Dos motivos. Uno, no se puede dar por hecho que la API envíe cabeceras CORS, así que un
`fetch()` desde el front puede morir en el navegador. Dos, `size` está limitado a 100 por
petición, así que "todas las últimas" implica paginar: eso no lo quieres haciendo cada
visitante, sino una vez por hora en el servidor.

El resultado: el sync pagina la API por su cuenta y deja un JSON plano. El React solo lee
ese fichero. Rápido, sin rate limits, y la tabla sigue viva si la API se cae.

Hay dos implementaciones equivalentes, `euvd_sync.mjs` (Node) y `euvd_sync.php`. La que
corre en producción es la de Node, lanzada por **GitHub Actions**; ver "Dónde corre el sync".

## Estructura en el hosting

```
docroot del subdominio/   ← NO ~/public_html, que es el dominio raíz y aloja otra web
├── index.html          ← build de Vite; lo sube deploy.yml en cada push al front
├── assets/             ← el bundle con hash, ídem
├── data/
│   ├── cves.json       ← lo sube el workflow en cada pasada
│   ├── cve_meta.json   ← caché de títulos y CWE de cve.org, también del workflow
│   ├── cwes_nvd.json   ← caché de las CWE que añade el NVD, ídem
│   ├── epss.json       ← última EPSS conocida de FIRST, red por si la API cae
│   └── kev_extra.json  ← fichas de lo explotado que cae fuera de la ventana
├── .vistas.json        ← qué entradas ha visto ya el feed; decide qué es nuevo
└── .notificado.json    ← qué se ha avisado ya por Telegram; fuera de data/, que se publica
```

El hosting no ejecuta nada: solo guarda lo que el workflow deja ahí. Las cachés y los dos
ficheros de estado viven aquí porque el runner de Actions es efímero y los necesita entre
pasadas — ver "Dónde corre el sync". El `.htaccess` bloquea `.vistas.json`,
`.notificado.json`, `.sync.lock` y los `.tmp`, que son estado interno y no datos del feed.

## Montaje

1. **Front.** `npm create vite@latest -- --template react`, y usa
   `FeedVulnerabilidades.jsx` como componente en `App.jsx`. No necesita Tailwind ni
   dependencias: los estilos van embebidos.

2. **Sync.** Pruébalo a mano antes de automatizar nada:

   ```bash
   npm run sync            # pasada completa
   npm run sync:rapido     # solo EUVD + cve.org + KEV
   ```

3. **Automatizarlo.** `.github/workflows/sync.yml` lo hace por ti; ver "Dónde corre el
   sync" para los secretos que hay que darle. Si prefieres cron en tu hosting, sube
   `euvd_sync.php` al directorio publicado —usa `__DIR__`, así que escribe en el `data/`
   que tenga al lado— y ponle las dos cadencias de "Dos cadencias".

4. **Cabeceras.** En `.htaccess`, para que el JSON no se quede pegado en caché:

   ```apache
   <Files "cves.json">
     Header set Cache-Control "max-age=300, must-revalidate"
   </Files>
   ```

## Dónde corre el sync

En **GitHub Actions**, no en el hosting: `.github/workflows/sync.yml`. Reutiliza
`euvd_sync.mjs` sin cambios, porque solo importa builtins de Node y no necesita
`npm install`.

Cada pasada hace tres cosas en este orden: baja el estado previo del servidor por FTP,
ejecuta el sync y sube el resultado. Ese primer paso es el que no se puede saltar — el
runner es efímero, así que sin él cada ejecución pediría los ~5.000 títulos a cve.org en
vez de los pocos nuevos, y Telegram volvería a sembrar `.notificado.json` sin avisar nunca
de nada. El servidor es la fuente de verdad de ese estado.

`cves.json` se sube a `.tmp` y se renombra, que es lo que hacía `escribir_json()` cuando el
script corría en el servidor: una subida de 6 MB por FTP no es atómica y un visitante podría
llevarse el JSON a medias.

Los secretos van en Settings → Secrets and variables → Actions:

| Secreto | Para qué |
|---|---|
| `FTP_HOST`, `FTP_USER`, `FTP_PASSWORD` | publicar el resultado |
| `NVD_API_KEY` | opcional; sube el límite del NVD de 5 a 50 peticiones/30 s |
| `VULNCHECK_API_TOKEN` | de lo que sale por Telegram: qué se avisa y con qué texto. Sin él la web sale igual pero no se avisa nada |
| `TELEGRAM_BOT_TOKEN` | opcional; sin él el sync corre igual y no avisa |
| `TELEGRAM_CHAT_KEV`, `_CRITICAS`, `_ALTAS`, `_MEDIAS`, `_BAJAS`, `_SIN_PUNTUAR` | una sala por criticidad; ver "Avisos por Telegram" |
| `TELEGRAM_CHAT_AVISOS` | opcional; sala de guardia para los fallos de la pasada, ver "Cuando algo se rompe" |

Y una **variable** del repo (Settings → Variables), que no es un secreto porque es una URL
pública: `SITIO_URL`, la raíz del feed publicado (`https://tu-subdominio.example/`). La usa
el chivato de frescura; sin ella queda apagado y lo dice en el resumen del run.

Las rutas del FTP son **relativas al directorio de entrada de la cuenta**, que debe ser el
docroot. El primer paso del workflow hace `ls data` justamente para verificarlo: si algún
día la cuenta aterrizara en otro sitio, el job corta ahí en vez de subir el feed a un
directorio que nadie sirve.

### Quién dispara las pasadas

La rápida la lanza **QStash de Upstash** cada 10 minutos, con un schedule que hace
`workflow_dispatch` contra la API de GitHub. No es un capricho: el `schedule` de Actions no
es puntual —los eventos programados se encolan y **se descartan en periodos de carga
alta**—, y pidiendo cada 15 minutos salían tres pasadas en ocho horas.

QStash reenvía al destino las cabeceras que le pases con el prefijo `Upstash-Forward-`; ahí
va un PAT de GitHub *fine-grained* limitado a este repositorio y con **solo `Actions: Read
and write`**, que es todo lo que necesita para lanzar el workflow y el mínimo daño posible
si se filtra.

La completa se queda en el `schedule` de GitHub a propósito, como red de seguridad: no
necesita puntualidad, y si QStash se cae o el token caduca, la web sigue actualizándose
cuatro veces al día en vez de quedarse congelada sin que nadie se entere — que es justo lo
que pasó con el cron del hosting.

El plan gratuito de QStash da 1.000 mensajes al día y 10 schedules; a 10 minutos se usan
144 y uno. Subir la frecuencia cabría de sobra en ese cupo, pero el límite real es otro:
cada pasada rápida pagina unas 50 peticiones a la EUVD, así que bajar a 5 minutos
duplicaría la carga sobre una API pública gratuita sin que llegue nada antes — la EUVD
publica en tandas durante el horario laboral europeo, no continuamente.

Dos avisos sobre el `schedule`. **Solo se ejecuta desde la rama por defecto**, así que en
una rama no arranca. Y a 15 minutos salían ~5.800 min/mes: por encima de los 2.000 que da
un repo privado, de ahí que este esté público — en repos públicos Actions es ilimitado.

### Cuando algo se rompe

Todo lo de arriba tiene una pega: **falla callándose**. Actions manda un correo cuando un
workflow *programado* falla, pero no cuando lo lanza QStash por `workflow_dispatch`, que son
143 de las 144 pasadas del día; y si QStash deja de disparar —schedule borrado, PAT caducado,
cuenta suspendida— no falla nada en ninguna parte: simplemente no corre nadie. Las dos veces
el resultado es el mismo que traía el cron del hosting, una web enseñando la tabla de
anteayer tan tranquila. Así que hay dos chivatos, y los dos avisan por el bot que ya está
montado:

- **La pasada ha fallado.** Un paso con `if: failure()` al final del workflow manda a la sala
  de guardia qué modo era y el enlace al run. No lleva freno: si el hosting está caído dos
  horas son doce avisos, y es lo que tiene que pasar — una alarma que se calla sola para no
  molestar no es una alarma.
- **El feed lleva demasiado sin moverse.** Antes de sincronizar, el workflow pide los
  primeros 200 bytes de `cves.json` a la web (`generado` es el primer campo del JSON, así que
  no hay que bajarse los 6 MB) y compara la hora con el reloj. Si pasan de 45 minutos —cuatro
  pasadas rápidas perdidas— avisa. Ojo a quién da la voz: si QStash se cae, las rápidas no
  corren y por tanto tampoco comprueban nada, así que quien lo detecta es la completa de cada
  6 h. Seis horas de retraso, frente a no enterarse nunca.

Los dos salen con 0 pase lo que pase: un chivato que tumba la pasada por no poder leer una
cabecera hace más daño que el fallo que vigila. Y sin `TELEGRAM_CHAT_AVISOS` el aviso cae en
la sala de KEV, o en `TELEGRAM_CHAT_ID`, para que un montaje sin sala propia se entere igual.

## Dos cadencias: pasada rápida y pasada completa

Las fuentes no cambian al mismo ritmo, así que el sync tiene dos modos. Medido sobre una
ventana de ~4.900 vulnerabilidades, con las cachés ya calientes:

| Fase | Completa | Rápida |
|---|---|---|
| Listado de la EUVD (50 páginas) | 35 s | 35 s |
| cve.org (solo las nuevas) | 1 s | 1 s |
| CWE del NVD | **105 s** | de caché |
| EPSS de FIRST | 30 s | de caché |
| KEV, catálogo | 1 s | 1 s |
| KEV, fichas de fuera de ventana (solo las nuevas) | 1 s | 1 s |
| **Total** | **190 s** | **35 s** |

La primera pasada tras estrenar `kev_extra.json` es la excepción: hay que pedir las ~1.300
fichas del catálogo una a una, unos 9 minutos. A partir de ahí solo se piden las que entren
nuevas, que son unas pocas por semana.

La pasada rápida (`--rapido`, o `SYNC_RAPIDO=1`) baja el listado, los títulos y CWE de lo
nuevo y el KEV, y lee de `cwes_nvd.json` y `epss.json` en vez de preguntar. No se pierde
nada: la puntuación viene en el propio listado de la EUVD, así que siempre está al día; las
filas ya enriquecidas conservan sus CWE y su EPSS, y las recién aparecidas las reciben en
la siguiente pasada completa (hasta entonces la EPSS sale como "No data", que es lo que ya
hacía).

Merece la pena porque **el modelo EPSS se recalcula una vez al día** y el NVD tarda en
enriquecer: pedirlos cada quince minutos es bajar los mismos números. Lo único que trae
vulnerabilidades nuevas es el listado de la EUVD, y cuesta 35 s.

Cada 10 min la rápida y cada 6 h la completa deja las vulnerabilidades nuevas en la web en
diez minutos en vez de en una hora, sin cuadruplicar el tráfico contra el NVD ni FIRST. El
JSON lleva un campo `modo` (`"rapido"` o `"completo"`) que dice cómo se generó.

## Un solo sync a la vez

Con una pasada cada 10 minutos y completas de tres, dos ejecuciones solapadas se pisarían
las cachés y el rename atómico. En Actions eso lo evita el `concurrency` del workflow; al
correr por cron, los dos scripts toman un cerrojo en `.sync.lock`
antes de empezar y, si ya hay otro corriendo, **salen con código 0** — no es un error, así
que el cron no te manda un correo cada cuarto de hora.

En PHP es `flock()`, que el sistema suelta al morir el proceso: no quedan cerrojos zombis.
Node no lo trae, así que usa un fichero con la hora de arranque y da por muerto lo que
lleve más de 30 minutos (`LOCK_CADUCIDAD_MS`); si no, una ejecución matada a medias
bloquearía el cron para siempre.

## Cómo llega el front a producción

`.github/workflows/deploy.yml`. Cada push a `main` que toque el front —el JSX, `src/`,
`public/`, `index.html`, la config de Vite o el `package.json`— hace `npm ci && npm run
build` y sube lo construido por el mismo FTP y con los mismos secretos que el sync. Un
commit que solo toca el sync o este README no mueve el bundle de producción.

Se sube en tres trozos, y ninguno puede tocar `data/`:

- **`assets/`** se espeja con `--delete`, que es lo que retira los bundles viejos. Al ser un
  directorio aparte, `data/` queda fuera de su alcance por construcción, no por cuidado.
- **`index.html`** va por `.tmp` y se renombra, para que nadie se lo lleve a medias y se
  quede sin bundle que cargar.
- **`.htaccess`** se sube porque el repo es su fuente de verdad: es quien bloquea
  `.notificado.json` y pone la caché de los JSON.

Ojo con `dist/data/`: Vite copia `public/` tal cual, así que en un portátil donde se haya
lanzado `npm run sync` ese directorio viene con los JSON dentro. No se sube nunca — los
datos los pone el otro workflow, y subir aquí una copia vieja de `cves.json` retrocedería
el feed varias horas de golpe.

Y luego comprueba, que subir sin mirar es la mitad del trabajo: saca del `index.html`
construido el nombre del bundle —lleva hash, así que no hay ambigüedad— y pide la web
hasta cinco veces, hasta verla servir ese bundle y que el fichero conteste 200. Si no
llega a cuadrar, el job falla, y un job que falla ahora avisa por Telegram.

**Por qué no el Git de hPanel**, que sería lo obvio. Ese despliegue clona el repo entero en
el docroot, y lo que el hosting tiene que servir no es el repo sino `dist/`: el `index.html`
de la raíz apunta a `/src/main.jsx`, que en producción no existe, así que la web saldría en
blanco. Sin SSH tampoco hay dónde ejecutar el build, de modo que habría que commitear
`dist/` y aun así acabarían publicados el README, el `package.json` y los dos `euvd_sync`.
Construir en Actions y subir solo lo construido evita las dos cosas.


## Avisos por Telegram

El sync avisa por Telegram según van apareciendo vulnerabilidades. Es solo de salida: no hay
bot a la escucha, ni webhook, ni proceso extra que mantener — el mismo cron que actualiza la
web hace un POST a `api.telegram.org` cuando encuentra algo nuevo.

### Todo sale de VulnCheck

Telegram va contra una sola fuente, y es VulnCheck. Dos cosas, que son independientes:

**Qué se avisa.** Al grupo solo llega lo que **VulnCheck KEV** da por explotado. Todo lo
demás sigue en la web —la tabla no cambia— pero no genera mensajes. Es el cambio que
convierte el grupo en otra cosa: de un boletín de 350 novedades al día a la lista de lo que
hay que parchear ya, que en una ventana real es **un puñado a la semana**.

**Qué dice el mensaje.** El texto no mezcla fuentes: el nombre, la descripción, el
fabricante, el producto, las CWE, las fechas, el ransomware, el plazo y las pruebas de
explotación salen de la ficha de VulnCheck KEV, y la puntuación y la fecha de publicación
del NVD que sirve el propio VulnCheck (`nist-nvd2`). Ver "Qué llega".

Se eligió VulnCheck y no CISA porque es el mismo dato pero antes y más ancho: 5.200 entradas
frente a las 1.700 de CISA KEV y EU KEV juntas, ninguna de las cuales falta aquí, y con la
fecha de confirmación uno o dos días por delante. Lo caro de una vulnerabilidad explotada es
enterarse tarde.

Lo que el filtro deja fuera **se anota igual**, con su firma y su sala, así que el día que lo
quites no te caen encima las dos semanas acumuladas: solo llega lo que aparezca a partir de
entonces. Y lo que se publicó antes de ponerlo no se borra: esos mensajes se quedan donde
están y su apunte se cae solo en `TG_OLVIDO_DIAS`, así que el grupo queda limpio en dos
semanas sin un barrido de cientos de borrados.

Sin `VULNCHECK_API_TOKEN`, o si el catálogo no baja, **la pasada no toca Telegram** y no
escribe el estado. Es a propósito: sin catálogo no se puede decidir qué avisar, y anotar lo
de hoy como visto sería perder su aviso para siempre. En diez minutos hay otra pasada.

Para quitar el filtro y volver al boletín completo, borra la llamada a `esVulncheckKev()` de
`notificarTelegram()` (`es_vulncheck_kev()` en el PHP): el resto del reparto por salas sigue
montado y vuelve a funcionar solo. El mensaje seguiría saliendo de VulnCheck, así que lo que
no esté en su catálogo iría sin datos; para eso hay que revertir `mensajeTelegram()` también.

### Las salas

Seis, por criticidad, más la de lo que ya se está explotando. Cada una es un grupo o canal
de Telegram, y **la sala que no tenga chat asignado no recibe nada**.

Con el filtro de VulnCheck puesto, todo lo que se manda está explotado, y KEV manda sobre la
puntuación: **el reparto acaba entero en `TELEGRAM_CHAT_KEV` y las otras cinco se quedan
mudas**. Siguen montadas y vuelven a llenarse solas el día que quites el filtro; la columna
"al día" es lo que recibiría cada una sin él:

| variable | qué recibe | al día |
|---|---|---|
| `TELEGRAM_CHAT_KEV` | consta explotada (con el filtro, todo lo que se manda) | 1 |
| `TELEGRAM_CHAT_CRITICAS` | CVSS ≥ 9.0 | 48 |
| `TELEGRAM_CHAT_ALTAS` | CVSS 7.0 – 8.9 | 134 |
| `TELEGRAM_CHAT_MEDIAS` | CVSS 4.0 – 6.9 | 123 |
| `TELEGRAM_CHAT_BAJAS` | CVSS < 4.0 | 23 |
| `TELEGRAM_CHAT_SIN_PUNTUAR` | todavía sin CVSS de nadie | 24 |

Las cifras son de una ventana real de 14 días. Separarlas es lo que hace la de KEV legible:
un mensaje al día y todos accionables, mientras el ruido se queda en las de abajo, que se
silencian desde el propio Telegram sin tocar el cron.

Cada vulnerabilidad va **a una sola sala**. KEV manda sobre la puntuación: una crítica que
además consta explotada va a la de KEV, no a las dos.

### Todas las salas en un solo grupo

El valor de cada sala puede ser un chat suelto (`-1001234567890`) o **un tema de un grupo
con foro** (`-1001234567890:7`, el tema 7 de ese grupo). Con lo segundo tienes las seis
salas dentro de un único grupo, cada una con su nombre y silenciable por separado, en vez
de seis conversaciones en la lista de chats.

Para montarlo: crea un grupo, *Gestionar grupo* → **Temas**, un tema por criticidad, y mete
al bot como administrador. Los canales no sirven — los temas solo existen en grupos.

El identificador de cada tema sale de su primer mensaje. Publica algo en cada uno y luego:

```bash
curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
```

En cada actualización, `message.message_thread_id` es el número que va detrás de los dos
puntos. Los identificadores de chat no llevan dos puntos, así que no hay ambigüedad posible
al partirlos.

### Montarlo

1. Habla con [@BotFather](https://t.me/BotFather), `/newbot`, y guarda el token
   (`123456789:AA…`). Es una credencial: quien la tenga puede escribir como tu bot.

2. Crea un grupo o canal por cada sala que quieras, mete al bot dentro —en un canal tiene
   que ser **administrador**— y publica algo en cada uno. Luego saca los identificadores:

   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```

   El `chat.id` sale en la respuesta. Los de grupo y canal van en negativo
   (`-1001234567890`), y el menos forma parte del id.

3. Dale al sync el token y las salas que hayas montado. En Actions son secretos del repo
   (ver "Dónde corre el sync"); en local, un `.env` a partir de `.env.example` —lo carga
   `npm run sync` solo, con `--env-file-if-exists`, que pide Node 20.18 o más— o los
   `export` a mano.

   Si lo lanzas por cron en un hosting, mete los `export` en un `euvd_env.sh` con
   `chmod 600` **fuera del directorio publicado** y sourcéalo desde la línea del cron. Usa
   rutas absolutas para todo: un `>>` a un directorio de logs que no existe hace fallar la
   redirección, y la shell aborta el comando entero antes de ejecutar el script — sin
   dejar rastro de por qué.

Sin token o sin ninguna sala, el sync corre exactamente igual y no avisa: la web no depende
de esto.

**Un solo grupo para todo.** Si no quieres salas separadas, define solo `TELEGRAM_CHAT_ID`:
recoge lo que no tenga sala propia, filtrado por `TELEGRAM_UMBRAL` (por defecto `7`, o sea
High y Critical, unas 183 al día). Lo que consta en KEV cae ahí aunque no llegue al umbral —
que algo se esté explotando importa aunque puntúe un 5. Las dos formas se pueden mezclar:
sala propia para KEV y críticas, y el respaldo para el resto.

**La primera ejecución no manda nada.** Siembra `.notificado.json` con lo que ya hay en la
ventana y se calla; a partir de la siguiente pasada solo llega lo nuevo. Si no, estrenar el
bot serían miles de mensajes de cosas de hace dos semanas.

### Qué llega

Un mensaje por vulnerabilidad, con lo justo para decidir sin abrir el enlace:

```
🔴 CRITICAL · CVSS 9.3 · CVE-2026-9586
Sangoma Switchvox SQL Injection Vulnerability

⚠️ Actively exploited — VulnCheck KEV · CISA KEV, added 2026-09-01
🔓 Known ransomware campaign use
📡 Exploitation seen by VulnCheck canaries

▎Sangoma Switchvox contains a SQL injection vulnerability which
▎allows an unauthenticated remote attacker to execute arbitrary SQL
▎statements against the backend PostgreSQL database…

Vendor: Sangoma
Product: Switchvox
CWE: CWE-89
Exploitability: 3.9 / 3.9 · Impact: 5.9 / 6.0
Published: 2026-08-14 17:15 UTC
Patch by: 2026-09-05

🛠️ Required action: Apply remediations or mitigations per vendor
instructions or discontinue use of the product if remediation or
mitigations are unavailable.

Evidence · Evidence 2 +30
```

**Cada línea sale de VulnCheck.** De la ficha del catálogo de KEV: el título, la descripción,
el fabricante, el producto, las CWE, la fecha en que entró, la de CISA si además la confirmó,
el plazo de parcheo, la acción recomendada y las pruebas de explotación. De su índice
`nist-nvd2`: el CVSS, sus dos subíndices y la fecha de publicación. De las métricas manda la
versión más alta que traiga —4.0 antes que 3.1— y, a igualdad de versión, la del asignador.

**Los subíndices van contra su tope**, que es lo que los hace legibles: un 1.8 de
explotabilidad no dice nada, un `1.8 / 3.9` dice que cuesta llegar. Separan dos cosas que el
score junta —lo fácil que es explotarla y lo que se lleva por delante— y no se mezclan entre
métricas: los dos salen de la misma que da la puntuación. Los topes cambian con la versión
(la 2.0 puntúa los dos sobre 10) y la 4.0 no los publica, así que ahí la línea no sale.

**La fecha de publicación lleva hora y dice que es UTC.** El NVD la sirve sin marca horaria,
y una fecha a secas hace pensar que la vulnerabilidad lleva un día entero fuera cuando puede
llevar veinte minutos.

**La acción recomendada** va entre los datos y los enlaces, que es donde le toca: lo de
arriba explica por qué corre prisa y esto dice qué se hace con ello. Es el campo
`required_action` **tal cual lo sirve el catálogo**: no se resume ni se reescribe, solo se
colapsan los espacios. El ejemplo de arriba es uno de sus textos literales.

Es plantilla —19 valores distintos para 1.000 entradas, y uno solo cubre dos tercios— pero
los hay de 488 caracteres, así que `TG_ACCION_MAX` (600) está para que uno futuro más largo
no se coma el margen hasta los 4.096 de un mensaje. Hoy no recorta ninguno.

Tres cosas que no daba ninguna otra fuente y ahora salen: **el uso conocido en campañas de
ransomware**, **la detección en los señuelos de VulnCheck** y **el plazo de parcheo**, que en
una lista de cosas que ya se están explotando es el único dato con una fecha límite de
verdad.

Y una que se ha ido: **la EPSS**, que la sirve FIRST y VulnCheck no. Tampoco pintaba mucho
—en un mensaje que solo habla de lo ya explotado, una probabilidad de que llegue a
explotarse sobra—, y la tabla la sigue enseñando.

El CVSS se pide **una petición por CVE, y solo de lo que de verdad se manda**: con el filtro
puesto son unos pocos por pasada, muy lejos de las 1.000 por minuto que deja el tier
community, así que no hace falta ni paginar ni cachear en disco.

**Los mensajes van en inglés.** Es el idioma de las fuentes —el título sale de cve.org, las
CWE de MITRE, los catálogos de CISA y ENISA—, así que traducir el envoltorio dejaba cada
mensaje a medio idioma. Los logs y el código siguen en castellano.

Cuatro bloques: cabecera, título, la alerta de explotación si la hay, los datos y los
enlaces. La cabecera va primera porque es lo único que se lee en la notificación del móvil,
y el identificador va en monoespaciada para poder copiarlo de un toque, que es lo primero
que se hace con un CVE.

Cada dato se calla si no lo hay, que es mejor que una fila con un guion: el producto solo si
difiere del fabricante; el plazo y la acción, solo si el catálogo los trae; los subíndices,
solo si la versión del CVSS los publica; el CVSS solo si el NVD de VulnCheck lo tiene, que si
no la cabecera se queda en `Unscored`.

**La línea de abajo son las referencias de VulnCheck y nada más**: las de
`vulncheck_reported_exploitation`, con las que sostiene que se está explotando. Unas son el
informe de quien lo vio, otras el aviso del fabricante, y son lo que se abre para verificar
el aviso.

Ni la ficha de la EUVD —iba primera por ser de donde salía el CVSS, y el CVSS ya no sale de
ahí— ni el registro del CVE: el identificador está arriba en monoespaciada, que es lo que se
copia. El catálogo trae **32 referencias de media** por CVE, así que se enseñan
`TG_EVIDENCIAS_VISIBLES` (2) y el resto se resume en un `+n`, igual que las CWE.

Las **CWE van enlazadas a cwe.mitre.org**, con el mismo tope de tres visibles y el mismo
`+n` que la tabla: en la pantalla de un móvil, seis identificadores seguidos ocupan más que
todo lo demás junto. Se descarta lo que no sea un `CWE-<número>` —los `NVD-CWE-noinfo` y
compañía—, que no tiene página a la que enlazar. Mandan las del catálogo de KEV, que van a la
causa de lo que se está explotando; las del NVD entran solo si el catálogo no trae ninguna.

**La descripción va en una cita plegable.** La mediana son 361 caracteres pero hay de 4.000,
así que por encima de `TG_DESC_PLEGABLE` (300) Telegram la colapsa y deja el resto del
mensaje a la vista; se despliega tocándola. `TG_DESC_MAX` (3.000) es un tope duro, porque un
mensaje entero no puede pasar de los 4.096 que admite la API. Los saltos de línea a media
frase se normalizan antes.

Y cuando el nombre que da el catálogo es el primer trozo de su propia descripción, el mensaje
**no repite la frase**: se queda solo con la descripción, que viene entera.

### Cuando una CVE cambia después de avisada

Los datos siguen moviéndose después del primer aviso: la EUVD ajusta la nota, FIRST recalcula
la EPSS, CISA mete la CVE en su catálogo. El sync mantiene el mensaje al día, y lo que hace
depende de si el cambio la saca o no de su sala.

**Si se queda en la misma sala** —un 3.1 que pasa a 3.4— el mensaje **se edita en el sitio**.
Telegram no notifica las ediciones de un bot, así que el mensaje se pone al día sin sonar,
sin moverse del tema y sin duplicarse. Al pie queda la hora, que si no el mensaje cambiaría
sin que se note:

```
Updated 2026-09-08 10:12 UTC
```

**Si cambia de sala**, el mensaje **se muda**: se publica en la sala nueva y se borra el de la
vieja. Un mensaje no se puede mover de un tema a otro, así que mudarse es la única forma de
que cada sala siga significando lo que dice. El mensaje nuevo abre diciendo de dónde viene:

```
⬆️ Escalated — previously reported as Low on 2026-09-04
⬇️ Downgraded — previously reported as Critical on 2026-09-04
```

Eso es lo que convierte la sala de KEV en algo útil: la mitad de lo que entra ahí son CVE de
las que ya se avisó hace días, y sin esa línea parecerían recién publicadas.

Las mudanzas van **en los dos sentidos**. Que la EUVD rebaje un 9.8 a un 5.0 no es una
noticia, pero dejar ese mensaje en la sala de críticas sí es un problema. Primero se publica
y luego se borra: si algo falla, es mejor un mensaje mal colocado que ninguno.

Para borrar mensajes de más de 48 horas el bot tiene que ser **administrador del grupo con
permiso de borrado**. Sin ese permiso las mudanzas dejan el mensaje viejo donde estaba y el
sync lo dice en el log.

**La EPSS se mira por bandas** —1 %, 10 % y 50 %—, no por decimales. El modelo de FIRST se
recalcula a diario y casi ninguna CVE conserva el mismo número de un día para otro: sin
bandas habría que reeditar las ~5.000 filas de la ventana todos los días, muy por encima de
lo que Telegram admite. El mensaje enseña el número exacto del día en que se editó.

Lo que sale de la ventana de 14 días deja de mantenerse: su último mensaje se queda
publicado tal cual.

### Nuevo no es reciente

Lo que decide si algo se avisa no es la fecha, es `.notificado.json`: un fichero con los
identificadores EUVD y, de cada uno, **a qué sala fue, con qué identificador de mensaje y con
qué firma** —un resumen de los campos que importan, que es lo que dice si hay que reeditar—,
junto al script y fuera de `data/`, que es un directorio que se publica.

Tiene que ser así porque la ventana de 14 días se solapa entre pasadas y porque los datos
llegan tarde: una CVE entra hoy sin CVSS, sale como "Sin puntuar" y recibe su 9.8 tres
pasadas después. Filtrando por fecha, esa no se avisaría nunca; llevando la cuenta de lo
enviado y de dónde, se avisa el día que le toca y no se repite.

El fichero se poda por **cuándo se vio la fila por última vez**, no por si aparece en la
pasada de ahora: lo que lleve más de `TG_OLVIDO_DIAS` (14) sin verse se olvida, y lo demás se
queda. La diferencia importa porque lo que trae una pasada no es la ventana, es lo que se ha
podido descargar de la ventana: una página de la EUVD que falla o un catálogo de KEV que no
baja dejan la lista a medias, y podando por presencia esos cientos de apuntes desaparecían.
Sin apunte, esas mismas filas cuentan como no avisadas en la pasada siguiente y se vuelven a
mandar — que es como acababan en la sala de KEV CVE de hace años.

Y como red aparte del fichero, **el primer aviso de una fila tiene que ser una noticia**. Lo
que trae la ventana lo es por definición: son catorce días de publicaciones. Lo que trae el
catálogo de KEV, no —la mayoría se explota desde hace años—, así que de esas solo se avisa si
entraron en el catálogo hace menos de `TG_DIAS_NOTICIA` (7 días). Una CVE de 2021 que CISA
añade hoy sí importa; la misma añadida en 2022, no. Aunque se pierda el estado entero, lo
viejo no vuelve a la sala.

El marcador `sembradoKev`, que anotaba el catálogo entero en silencio la primera vez, **solo
actúa si no hay registro de vistas**. Con `.vistas.json` sembrado el volcado ya es imposible
—a Telegram solo le llega lo que el registro da por nuevo— y callarse el primer KEV nuevo
sería perder el aviso que más importa. La red se queda para un montaje sin registro.

El filtro solo decide el **primer** aviso. Una fila ya anotada sigue su camino por vieja que
sea: si cambia se edita en el sitio, y si cambia de sala se muda a la que le toque.

Las filas cuya sala no está montada **se anotan igual, sin enviarse**. Por eso el día que
añadas la sala de medias no te caen encima las 1.700 de la ventana: solo llega lo que
aparezca a partir de entonces. Y si vienes de la versión de un solo chat, el fichero de
estado se reconstruye solo en la primera pasada, también sin avisar.

Las entradas anotadas antes de que se guardara el identificador de mensaje no se pueden ni
editar ni mudar: se les apunta la firma, siguen contando para no reavisar, y en 14 días salen
de la ventana solas. Lo que se publique a partir de ahí ya nace editable.

### El ritmo

Como mucho salen `TG_MAX_MENSAJES` (12) avisos **por sala** y pasada, con una pausa de 3,5 s
entre mensajes. Ojo con esa pausa: el límite que manda no es el del chat sino **el del
grupo**, unos 20 mensajes por minuto, y con las salas montadas como temas de un mismo grupo
todas comparten ese tope. A 1,2 s el sync iba a ~50/min y Telegram respondía 429; a 3,5 s se
queda en ~17/min. El tope es por sala a propósito — un atasco en medias no debe retrasar el aviso de
una crítica. Lo que no quepa **no se pierde ni se marca**, sale en la pasada siguiente. Si
aun así llega un 429, el sync corta los envíos ahí y lo retoma en la siguiente.

La cola sale ordenada por sala y luego por puntuación, así que si un día hay atasco, lo que
ya se está explotando va delante.

Las ediciones y los borrados cuentan contra ese mismo tope del grupo, así que van por el
mismo contador de pausas. Las ediciones tienen su propio tope, `TG_MAX_EDICIONES` (40 por
pasada), y van al final: como no notifican a nadie, lo justo es que cedan el turno a los
avisos cuando la pasada se queda corta.

Los avisos van **después** de escribir `cves.json` a propósito: que Telegram no conteste no
puede dejar la web sin actualizar. Todo lo que pasa —lo enviado por sala, lo encolado, los
errores— queda en el log de la ejecución.

### El freno de mano

`TELEGRAM_PAUSA=1` para Telegram sin parar el sync: la pasada descarga, enriquece y publica
la web igual que siempre, pero no manda, no edita y no borra nada en el grupo. Va como
**variable del repo** (Settings → Variables), no como secreto ni como constante, para poder
ponerla y quitarla sin tocar el código ni esperar a un despliegue.

Lo importante es lo que hace con lo que sale mientras está puesta: **lo anota en silencio**,
como una siembra, en vez de encolarlo. Una pausa que guarda todo lo que no mandó es una bomba
de relojería —al quitarla saldrían de golpe los avisos de todos los días que estuvo parada—,
y de eso iba precisamente ponerla. Así que al reanudar solo llega lo que aparezca **a partir
de ese momento**; lo de la pausa no se avisa nunca.

Lo que ya estaba publicado conserva su apunte —sala e identificador de mensaje—, así que al
reanudar se puede seguir editando y mudando en vez de duplicarlo.

### Lo que el feed ya ha visto

Borrar el feed no basta para empezar de cero: la pasada siguiente vuelve a pedir los 14 días
a la EUVD, lo rellena entero y Telegram toma por novedad todo lo que no tenga anotado. Así
salieron 900 avisos encolados de vulnerabilidades de hasta dos semanas.

Lo que lo evita es `.vistas.json`, la memoria del feed: por cada identificador EUVD, **cuándo
se vio por primera vez** y cuándo se vio por última. Con eso, lo que se publica en la web y
lo que se avisa por Telegram —que son la misma lista, filtrada en un solo sitio— es
únicamente lo que no se había visto antes.

- **La primera pasada no publica nada.** Anota lo que hay y deja constancia en el log de
  cuál es la última entrada. Es la "primera revisión": el fondo del que se parte.
- **A partir de la segunda**, entra lo que no esté en esa lista, venga de la ventana o del
  catálogo de KEV, y se queda **`VENTANA_DIAS` (14) días desde que se vio**, no desde que se
  publicó. Lo del fondo inicial no entra nunca.
- Una entrada deja de estar en el registro cuando lleva `VISTAS_OLVIDO_DIAS` (14) sin
  aparecer. Ni un día menos: si se olvidara mientras la EUVD todavía la devuelve, la pasada
  siguiente la tomaría por nueva y la volvería a ingerir.

**Por qué por identificador y no por fecha.** La EUVD ordena por fecha de actualización, no
de publicación, y las fichas asoman tarde: hay entradas publicadas hora y media antes de
aparecer en el listado, y el catálogo rellena huecos hacia atrás. Un corte por reloj dejaría
fuera **para siempre** todo lo que se publique antes del corte y aparezca después, que en un
feed de vulnerabilidades es justo lo que no se puede perder. Con el registro da igual qué
fecha traiga: si no se había visto, es nueva.

**Para volver a empezar**, se borra `.vistas.json` del servidor y la pasada siguiente vuelve
a ser la primera revisión: web vacía y a acumular. Si además quieres que Telegram olvide lo
avisado, eso es `reiniciar-avisos.yml`, que borra `.notificado.json`; son dos cosas
distintas y se pueden hacer por separado.

En `cves.json` quedan `desdeCero` —cuándo se hizo la primera revisión— y `conocidas` —cuántas
entradas lleva vistas—, y la web dice que se está llenando mientras no haya pasado una
ventana entera desde entonces. Cada pasada deja en el log cuántas entraron nuevas y cuántas
se retiraron por antigüedad.

## Parámetros que querrás tocar

En `euvd_sync.mjs` y `euvd_sync.php` (los nombres son equivalentes en ambos):

- `VENTANA_DIAS` — días hacia atrás. 14 da un volumen manejable; 30 engorda bastante el JSON.
  No afecta a lo que siembra el catálogo de KEV: eso entra por estar explotado, no por
  reciente, y sale marcado con `fueraDeVentana`.
- `MAX_PAGINAS` — tope de seguridad. 100 páginas = 10.000 registros. **No lo bajes sin
  mirar el log**: si la ventana tiene más vulnerabilidades de las que caben, el sync avisa
  con un `AVISO:` y la web saca una banda, porque lo que se pierde no son las más antiguas
  sino las que la API no llegue a devolver. Con 14 días son ~6.000, así que 25 páginas se
  quedaban con la cuarta parte y 60 se quedaron cortas el 2026-09-08. Y quedarse corto no es
  solo publicar una web incompleta: **lo que falta hoy entra mañana como si acabara de
  salir**, que fue lo que llenó la cola de Telegram con 900 avisos de vulnerabilidades de
  hasta dos semanas.
- `VISTAS_OLVIDO_DIAS` — cuánto se recuerda una entrada que ha dejado de aparecer. **No lo
  bajes de `VENTANA_DIAS`**: olvidar antes de que la EUVD deje de devolverla es reingerirla
  entera. Ver "Lo que el feed ya ha visto".
- `VULNCHECK_SIEMBRA_DIAS` — cuánto hacia atrás se siembra lo que solo consta en VulnCheck.
  Subirlo engorda la tabla y la pasada sin ganar avisos: por encima de `TG_DIAS_NOTICIA` (7)
  lo que entra ya no se avisa, solo se publica.
- `TG_EVIDENCIAS_VISIBLES` — referencias de explotación enlazadas en el mensaje, que son los
  únicos enlaces que lleva. 2 llegan para verificarlo; el catálogo trae 32 de media por CVE,
  y las que no caben se cuentan en el `+n`.
- `TG_ACCION_MAX` — tope de la acción recomendada. La más larga que sirve hoy el catálogo
  mide 520 caracteres.
- `TG_CVSS_TOPES` — a cuánto llega cada subíndice en cada versión del CVSS. Solo se toca si
  el NVD empieza a publicar subíndices de la 4.0.
- `TELEGRAM_PAUSA` — variable de entorno, no constante; ver "El freno de mano".
- `PAUSA_US` / `PAUSA_MS` — pausa entre peticiones. No lo bajes de 0,3 s.
- `CONCURRENCIA_TITULOS` — peticiones simultáneas a cve.org. 6 va sobrado; subirlo
  arriesga que te empiecen a devolver 429.
- `NVD_MARGEN_DIAS` — días extra de margen al pedir las CWE al NVD (ver más abajo).
- `EPSS_TANDA` — CVE por petición a FIRST. 100 es el máximo que admite la API.
- `NVD_API_KEY` — variable de entorno opcional, solo para la descarga de CWE. Sin ella el
  NVD deja 5 peticiones cada 30 s; con ella, 50. Se pide gratis en
  <https://nvd.nist.gov/developers/request-an-api-key> Es el secreto `NVD_API_KEY` del repo.
- `VULNCHECK_API_TOKEN` — variable de entorno. Es de lo que vive Telegram: decide qué se
  avisa y de dónde sale el texto. Sin ella la web sale igual pero no se avisa nada. Se pide
  gratis en <https://vulncheck.com> (tier community). Es el secreto `VULNCHECK_API_TOKEN`
  del repo.

Con la ventana entera, más las ~1.300 que siembra el catálogo de KEV, el JSON ronda los
7,5 MB, así que **sirve el `data/` con gzip**
(`AddOutputFilterByType DEFLATE application/json` en el `.htaccess`); baja a ~1 MB. Si aun
así se hace grande, lo siguiente es partirlo por días o acortar `VENTANA_DIAS`.

## De dónde sale el título

La EUVD no tiene campo de título, solo `description`. Así que el nombre de cada fila se
pide a cve.org (`https://cveawg.mitre.org/api/cve/CVE-…`) y se lee `containers.cna.title`,
que es el título que le puso el propio CNA.

Ese campo es opcional en el esquema CVE 5.x, y un CVE recién reservado da 404 aunque la
EUVD ya lo liste. Cuando no hay título se cae al respaldo de siempre: la primera frase de
la descripción recortada a 140 caracteres (`nombre_corto()`).

Como son ~2.500 CVE por ejecución y el cron va cada hora, la respuesta de cve.org se cachea
en `data/cve_meta.json` (título y CWE en la misma entrada) y solo se piden los que aún no
estén ahí. Los fallos no se cachean, de forma que un CVE que hoy da 404 se reintenta en la
siguiente pasada. La caché se reescribe en cada ejecución con los CVE que siguen dentro de
la ventana, para que no crezca sin fin.

La primera ejecución es la lenta (baja los ~2.500 registros); las siguientes solo tocan las
CVE nuevas. Si borras `cve_meta.json`, se vuelve a construir entero. El antiguo
`titulos.json` ya no se usa: se puede borrar.

## De dónde sale la puntuación

La CVSS que se muestra es la de la **EUVD** (`baseScore`, con `baseScoreVersion` y
`baseScoreVector`), que es la que le pasa el CNA y la que enseña la ficha que se enlaza.
Viene en el propio listado, así que no cuesta ni una petición extra y está al día también
en la pasada rápida.

**Antes se pisaba con la del NVD y se dejó de hacer**: el NIST reanaliza por su cuenta y a
veces no encajaba con la ficha de la EUVD —otra versión del CVSS, otro alcance—, así que
una misma fila podía enseñar un número y su descripción contar otra cosa. Con una sola
fuente, el score y el texto siempre hablan de lo mismo. El campo `origenScore` que decía
de dónde venía cada nota ya no existe, ni en el JSON ni en la tabla.

La EUVD manda `baseScore: 0` cuando no hay CVSS: eso se trata como hueco, no como un cero,
y la fila sale como "Sin puntuar".

## De dónde salen las CWE

La columna CWE es la debilidad de fondo: el *por qué* técnico de la vulnerabilidad
(CWE-79 XSS, CWE-78 inyección de comandos, CWE-787 escritura fuera de límites…), no su
gravedad. Sale de `containers.cna.problemTypes` del registro de cve.org, que se pide en la
misma llamada que el título, así que no cuesta ni una petición extra. También se leen los
contenedores ADP, que es donde CISA y los enriquecedores meten las suyas.

Cuando cve.org no trae ninguna, se cae al `weaknesses` del NVD. Ahí solo está el
identificador, sin el nombre, así que la fila enseña "CWE-89" a secas.

Esa parte no se pide CVE a CVE: la API del NVD admite 5 peticiones cada 30 s sin clave, así
que 2.500 consultas serían horas. En vez de eso se baja **por rango de fechas de
publicación** (`pubStartDate`/`pubEndDate`, 2.000 por página), que resuelve la ventana
entera en unos segundos. El rango lleva `NVD_MARGEN_DIAS` de margen hacia atrás porque la
fecha de publicación del NVD no tiene por qué coincidir con la de la EUVD, y lo bajado se
cachea en `data/cwes_nvd.json` igual que los títulos: si el NVD se cae o devuelve 503, la
tabla sigue enseñando las últimas CWE conocidas. Es la fase más lenta del sync, y por eso
la pasada rápida la lee de caché.

Cada CWE se guarda como `{ id, nombre }` en `cwes[]`. Se descarta lo que no lleva número
—`n/a`, `Other`, `NVD-CWE-noinfo`—: un hueco es más honesto que una etiqueta vacía.

La tabla enseña **los identificadores**, hasta `CWE_VISIBLES` (3) y un `+n` con el resto en
el tooltip. El nombre no va en la celda: ocupaba media columna para decir lo mismo que el
identificador, y una CVE con tres CWE cuenta más que una con la descripción de una sola.
El nombre completo sigue en el `title` de cada enlace y en el detalle de la fila, que las
lista todas enlazadas a `cwe.mitre.org`.

## De dónde sale la EPSS

La EPSS (*Exploit Prediction Scoring System*) es la probabilidad de que una CVE se explote
en los próximos 30 días. No mide gravedad, mide **actividad esperada**: un 9.8 de CVSS con
un 0,04 % de EPSS urge menos que un 7.5 con un 40 %.

La EUVD trae un campo `epss`, pero tiene dos problemas: llega en porcentaje (1.55 = 1,55 %,
no el 155 % que salía al multiplicar por 100) y vale 0 en todo lo recién publicado, que es
justo lo que enseña este feed. Por eso se pide a la fuente, la API de FIRST
(`https://api.first.org/data/v1/epss`), en tandas de 100 CVE, que es el máximo por
petición: la ventana entera son ~25 llamadas y unos pocos segundos.

Aquí no vale cachear y no volver a preguntar como con los títulos, porque **el modelo se
recalcula a diario**: se piden todas en cada pasada y `data/epss.json` solo sirve de red
por si FIRST no responde.

**Lo recién publicado no tiene EPSS y eso es normal.** El modelo tarda unos días en
incorporar una CVE nueva, así que las primeras filas de la vista por defecto ("más
recientes") salen con "Sin dato" — no con un 0, que sería afirmar que no la va a explotar
nadie. Con la ventana de 14 días suelen ser unas 35-40 de 2.500, todas del último día o
dos. Para ver la columna con datos, ordena por "EPSS más alto".

Cada fila lleva `epss` (probabilidad 0-1, como la publica FIRST), `epssPercentil` (qué
porcentaje del catálogo queda por debajo), `epssFecha` (día del modelo) y `origenEpss`
(`"first"`, o `"euvd"` si FIRST no contestó y se conserva el respaldo). Los cortes de color
de la tabla son 1 %, 10 % y 50 %: parecen bajos, pero la mediana del catálogo no llega al
0,1 %.

## Lo que ya se está explotando (KEV)

La EPSS estima la probabilidad de que alguien explote una CVE. El **KEV** no estima nada:
dice que ya está pasando. Son cosas distintas y las dos hacen falta.

Y no se solapan tanto como parecería. De las filas del feed que constan en KEV, casi todas
andan **por debajo del 1 % de EPSS** — CVE con explotación confirmada que, ordenando por
EPSS, no salen ni en la página veinte. Por eso van marcadas aparte y no como un EPSS alto.

Salen de dos sitios. `https://euvdservices.enisa.europa.eu/api/kev/dump` consolida CISA KEV
y EU KEV en una sola respuesta sin paginar: una petición, ~1.700 entradas, cruzadas por
`cveId` y, si no, por `euvdId`. Y `https://api.vulncheck.com/v3/index/vulncheck-kev` trae
el de VulnCheck: ~5.200 entradas, seis peticiones de 1.000 con `Authorization: Bearer`, y se
cruza solo por CVE, que es lo único que da.

Las filas que caen en cualquiera de los dos llevan `kev: { fecha, fuentes }` —`fuentes` es
`vulncheck_kev`, `cisa_kev`, `eukev_kev` o varias—, borde izquierdo rojo, un distintivo
"Explotada" junto al CVE y un chip de filtro propio en la barra. Cuando los dos catálogos la
traen, **manda la fecha más antigua**: lo que importa es desde cuándo consta explotada, no
cuál de los dos se enteró el último.

El tier community de VulnCheck es gratis y basta: 1.000 peticiones por minuto contra las seis
que se hacen. Lo único que corta es la paginación, que se para en 6 páginas; hoy sobran, y el
sync avisa en el log en cuanto el catálogo no quepa, porque a partir de ahí el filtro de
Telegram se dejaría fuera lo que no haya bajado.

Si un catálogo no responde, las filas se quedan sin su marca y el resto del sync sigue: para
la tabla es un dato que suma, no uno del que dependa. Para Telegram no, porque el de VulnCheck
es el que decide qué se avisa y con qué texto; ver "Todo sale de VulnCheck".

### El catálogo también trae filas, no solo marcas

La búsqueda de la EUVD filtra por **fecha de publicación**, así que una CVE publicada en
abril y explotada desde mayo no aparecía por ningún lado: ni en la web ni en la sala de KEV,
por muy grave que fuera. Marcar no bastaba, porque solo se marca lo que ya se ha descargado.

Así que el catálogo siembra: de cada entrada que no venga en la ventana se pide su ficha a
`/api/enisaid?id=…` y se añade al listado, marcada con `fueraDeVentana: true`. Pasa por los
mismos enriquecidos que el resto (título de cve.org, CWE, EPSS); las CWE del NVD sí se las
pierde, porque esas se piden por ventana de publicación y cve.org es la fuente principal.

Del catálogo de la EUVD se siembra todo. Del de VulnCheck, **solo lo añadido en los últimos
`VULNCHECK_SIEMBRA_DIAS` (14)**: son ~3.500 CVE que la EUVD no marca, casi todas de hace
años, y pedir sus fichas una a una serían veinte minutos por pasada para triplicar la tabla
con cosas que no son noticia. Lo que hace falta es lo que acaba de entrar, que además es lo
único que `TG_DIAS_NOTICIA` deja avisar. Y hace falta de verdad: de lo que VulnCheck añadió
en una semana real, **la mayoría eran CVE de 2023 a 2025** que la ventana no alcanza — sin
sembrarlas no habría fila, y sin fila no hay aviso por muy explotadas que estén.

Como VulnCheck no da ids de la EUVD, esas fichas se piden por CVE. `/api/enisaid?id=…` acepta
las dos cosas, así que el resto del camino es el mismo.

Las fichas se guardan en `data/kev_extra.json` y la caché se poda con el catálogo: lo que
CISA, la EUVD o VulnCheck retiran deja de publicarse aquí también.

El recuento de la cabecera lo dice separado ("N in the last 14 days + M older") y en el JSON
está `fueraDeVentana` con cuántas son. `totalEnEuvd` sigue siendo lo que la EUVD dice tener
en la ventana, sin lo sembrado: es con lo que se compara el aviso de paginación corta.

En Telegram, la primera pasada con catálogo **anota las ~1.300 sin avisar** y deja la marca
`sembradoKev` en `.notificado.json`. Sin eso, estrenar esto habría vaciado el catálogo entero
en la sala de KEV: más de una hora de mensajes sobre cosas explotadas desde hace años. A
partir de ahí sí llega lo que entre nuevo en el catálogo, que es el mismo trato que reciben
las salas recién montadas. Si el catálogo falla en esa pasada, la marca no se pone y la
siembra espera a la siguiente.

Esa marca es de un solo uso, así que no basta: lo que de verdad sostiene la sala es el filtro
de `TG_DIAS_NOTICIA` — de fuera de la ventana solo se avisa lo que acaba de entrar en el
catálogo. Ver "Nuevo no es reciente".

## El top por prioridad

Sobre la tabla hay un panel plegable con las `TOP_N` (10) más urgentes de la ventana. Sale
de todas las filas, no de las filtradas: es el top de los 14 días, no el de lo que tengas
buscado en ese momento. Pulsar una tarjeta busca esa CVE en la tabla y le abre el detalle.

El orden lo decide `prioridad()`, en dos escalones:

1. **Lo que consta en KEV.** Ahí la explotación no es una estimación, es un hecho. Entre
   ellas ordena la EPSS —que en este escalón ya no mide "si pasará" sino cuánta actividad
   hay— y el CVSS desempata.
2. **El resto, por EPSS × impacto** (`epss * score / 10`): lo probable que es por lo que
   cuesta si pasa. Sin EPSS o sin CVSS no hay con qué priorizar y la fila cae al final.

Ninguna señal sola vale para esto. Por CVSS hay cientos empatadas en 10.0 y el corte lo
acabaría decidiendo la fecha; por EPSS se hunden 13 de las 14 que ya se están explotando,
algunas por debajo del percentil 40.

**Ojo con `TOP_N`:** si hay 10 o más entradas de KEV en la ventana, el top se llena entero
con el primer escalón y el segundo no llega a verse. Con los datos de ejemplo (14 en KEV)
pasa justo eso. Si quieres que asomen siempre las de EPSS alto, sube `TOP_N` a 15-20 o
reserva huecos por escalón.

## Cosas a tener en cuenta

- **Un fabricante por fila.** La API devuelve `enisaIdVendor` como array. La tabla muestra
  el primero; el resto queda en `vendors[]` dentro del JSON si lo quieres usar.
- **Filas sin puntuación.** Hay CVE sin CVSS asignado. Aparecen como "Sin puntuar" en vez
  de como 0.0, que sería engañoso. La EUVD manda `baseScore: 0` en esos casos y se trata
  como hueco, no como un cero real. Con la EPSS pasa lo mismo: sin dato va un guion.
- **CVSS y EPSS no se ordenan igual.** El selector permite ordenar por las dos. Ordenar por
  EPSS es lo que responde a "¿qué parcheo esta semana?"; por CVSS, a "¿qué es más grave si
  pasa?".
- **No todas las entradas EUVD tienen CVE.** Algunas solo traen GHSA u otros identificadores.
  En ese caso la tabla enseña el ID EUVD en la columna CVE.
- **El enlace apunta al NVD** (`https://nvd.nist.gov/vuln/detail/CVE-…`). Ojo: desde abril
  de 2026 muchas CVE se quedan sin enriquecer en el NVD, así que alguna ficha puede salir
  con datos escasos o en estado "Awaiting Analysis" — de ahí que tampoco se le pida ya la
  puntuación. La alternativa es cve.org
  (`https://www.cve.org/CVERecord?id=CVE-…`). Se cambia en `normalizar()`. Los avisos de
  Telegram sí enlazan la ficha de la EUVD, que es la que enseña el CVSS del mensaje.
- **Endpoints alternativos** por si más adelante quieres otras vistas:
  `/api/criticalvulnerabilities`, `/api/exploitedvulnerabilities` y `/api/kev/dump`
  (CISA KEV + EU KEV consolidados, actualizado a diario a las 07:00 UTC).
