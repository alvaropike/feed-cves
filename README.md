# Feed de vulnerabilidades (EUVD)

Tabla web con las CVE publicadas recientemente: CVE, nombre, fabricante, CWE, criticidad,
EPSS y fecha. Fuentes: EU Vulnerability Database de ENISA para el listado y la puntuación
CVSS, cve.org para el título oficial y las CWE de cada CVE —con el NVD del NIST de
respaldo para las CWE—, FIRST para la EPSS y los catálogos CISA KEV / EU KEV para marcar
lo que ya se está explotando.
Opcionalmente avisa por Telegram, con una sala por criticidad y otra para lo que ya se
está explotando; ver más abajo.

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
public_html/
├── index.html          ← build de Vite
├── assets/
├── data/
│   ├── cves.json       ← lo sube el workflow en cada pasada
│   ├── cve_meta.json   ← caché de títulos y CWE de cve.org, también del workflow
│   ├── cwes_nvd.json   ← caché de las CWE que añade el NVD, ídem
│   ├── epss.json       ← última EPSS conocida de FIRST, red por si la API cae
│   └── kev_extra.json  ← fichas de lo explotado que cae fuera de la ventana
└── .notificado.json    ← qué se ha avisado ya por Telegram; fuera de data/, que se publica
```

El hosting no ejecuta nada: solo guarda lo que el workflow deja ahí. Las cachés y
`.notificado.json` viven aquí porque el runner de Actions es efímero y las necesita entre
pasadas — ver "Dónde corre el sync". El `.htaccess` bloquea `.notificado.json`, `.sync.lock`
y los `.tmp`, que son estado interno y no datos del feed.

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
| `TELEGRAM_BOT_TOKEN` | opcional; sin él el sync corre igual y no avisa |
| `TELEGRAM_CHAT_KEV`, `_CRITICAS`, `_ALTAS`, `_MEDIAS`, `_BAJAS`, `_SIN_PUNTUAR` | una sala por criticidad; ver "Avisos por Telegram" |

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

## Avisos por Telegram

El sync avisa por Telegram según van apareciendo vulnerabilidades, **cada una a la sala que
le toca**. Es solo de salida: no hay bot a la escucha, ni webhook, ni proceso extra que
mantener — el mismo cron que actualiza la web hace un POST a `api.telegram.org` cuando
encuentra algo nuevo.

### Las salas

Seis, por criticidad, más la de lo que ya se está explotando. Cada una es un grupo o canal
de Telegram, y **la sala que no tenga chat asignado no recibe nada**:

| variable | qué recibe | al día |
|---|---|---|
| `TELEGRAM_CHAT_KEV` | consta en CISA KEV o EU KEV | 1 |
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
   (ver "Dónde corre el sync"); en local, un `.env` a partir de `.env.example`, o los
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
🔴 CRITICAL · CVSS 9.8 · CVE-2026-60004
Gitea allows remote code execution via the diffpatch API

⚠️ Actively exploited — CISA KEV · EU KEV, added 2026-08-26

▎Gitea before 1.27.1 allows remote code execution via the diffpatch
▎API through Git hook installation. Exploitation requires an account
▎with repository write access…

Vendor: Gitea
Product: Gitea Enterprise
EPSS: 86.8% (percentile 99)
CWE: CWE-94, CWE-78
Published: 2026-08-26

EUVD · CVE Record
```

**Los mensajes van en inglés.** Es el idioma de las fuentes —el título sale de cve.org, las
CWE de MITRE, los catálogos de CISA y ENISA—, así que traducir el envoltorio dejaba cada
mensaje a medio idioma. Los logs y el código siguen en castellano.

Cuatro bloques: cabecera, título, la alerta de explotación si la hay, los datos y los
enlaces. La cabecera va primera porque es lo único que se lee en la notificación del móvil,
y el identificador va en monoespaciada para poder copiarlo de un toque, que es lo primero
que se hace con un CVE.

Cada dato se calla si no lo hay, que es mejor que una fila con un guion: la EPSS
solo aparece si FIRST ya tiene dato —lo recién publicado no lo tiene, y un 0 sería mentir—;
el producto solo si difiere del fabricante; el CVSS solo si la EUVD lo ha puesto, que si no
la cabecera se queda en `Unscored`; y el enlace a cve.org, solo si la fila tiene CVE.

**El primer enlace es la ficha de la EUVD**, que es de donde sale el CVSS del mensaje. Antes
iba al NVD, pero mandar a una ficha que puntuaba otra cosa —o que sigue en "Awaiting
Analysis"— era justo lo que hacía dudar del número.

Las **CWE van enlazadas a cwe.mitre.org**, con el mismo tope de tres visibles y el mismo
`+n` que la tabla: en la pantalla de un móvil, seis identificadores seguidos ocupan más que
todo lo demás junto. Se descarta lo que no sea un `CWE-<número>` —los `NVD-CWE-noinfo` y
compañía—, que no tiene página a la que enlazar.

**La descripción va en una cita plegable.** La mediana son 361 caracteres pero hay de 4.000,
así que por encima de `TG_DESC_PLEGABLE` (300) Telegram la colapsa y deja el resto del
mensaje a la vista; se despliega tocándola. `TG_DESC_MAX` (3.000) es un tope duro, porque un
mensaje entero no puede pasar de los 4.096 que admite la API. Los saltos de línea a media
frase que trae la EUVD se normalizan antes.

Y cuando cve.org no tiene título —una de cada cuatro filas—, `nombre` es el primer trozo de
la propia descripción. En ese caso el mensaje **no repite la frase**: se queda solo con la
descripción, que además viene entera.

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
enviado y de dónde, se avisa el día que le toca y no se repite. El fichero se poda en cada
ejecución con las que siguen dentro de la ventana, igual que las demás cachés.

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

## Parámetros que querrás tocar

En `euvd_sync.mjs` y `euvd_sync.php` (los nombres son equivalentes en ambos):

- `VENTANA_DIAS` — días hacia atrás. 14 da un volumen manejable; 30 engorda bastante el JSON.
  No afecta a lo que siembra el catálogo de KEV: eso entra por estar explotado, no por
  reciente, y sale marcado con `fueraDeVentana`.
- `MAX_PAGINAS` — tope de seguridad. 60 páginas = 6.000 registros. **No lo bajes sin
  mirar el log**: si la ventana tiene más vulnerabilidades de las que caben, el sync avisa
  con un `AVISO:` y la web saca una banda, porque lo que se pierde no son las más antiguas
  sino las que la API no llegue a devolver. Con 14 días son ~5.000, así que 25 páginas se
  quedaban justo con la mitad.
- `PAUSA_US` / `PAUSA_MS` — pausa entre peticiones. No lo bajes de 0,3 s.
- `CONCURRENCIA_TITULOS` — peticiones simultáneas a cve.org. 6 va sobrado; subirlo
  arriesga que te empiecen a devolver 429.
- `NVD_MARGEN_DIAS` — días extra de margen al pedir las CWE al NVD (ver más abajo).
- `EPSS_TANDA` — CVE por petición a FIRST. 100 es el máximo que admite la API.
- `NVD_API_KEY` — variable de entorno opcional, solo para la descarga de CWE. Sin ella el
  NVD deja 5 peticiones cada 30 s; con ella, 50. Se pide gratis en
  <https://nvd.nist.gov/developers/request-an-api-key> Es el secreto `NVD_API_KEY` del repo.

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

Sale de `https://euvdservices.enisa.europa.eu/api/kev/dump`, que consolida CISA KEV y EU KEV
en una sola respuesta sin paginar: una petición por ejecución, ~1.700 entradas. Se cruza por
`cveId` y, si no, por `euvdId`. Las filas que caen dentro llevan
`kev: { fecha, fuentes }` (`fuentes` es `cisa_kev`, `eukev_kev` o las dos), borde izquierdo
rojo, un distintivo "Explotada" junto al CVE y un chip de filtro propio en la barra.

Si el catálogo no responde, las filas se quedan sin marcar y el resto del sync sigue: es
un dato que suma, no uno del que dependa la tabla.

### El catálogo también trae filas, no solo marcas

La búsqueda de la EUVD filtra por **fecha de publicación**, así que una CVE publicada en
abril y explotada desde mayo no aparecía por ningún lado: ni en la web ni en la sala de KEV,
por muy grave que fuera. Marcar no bastaba, porque solo se marca lo que ya se ha descargado.

Así que el catálogo siembra: de cada entrada que no venga en la ventana se pide su ficha a
`/api/enisaid?id=…` y se añade al listado, marcada con `fueraDeVentana: true`. Pasa por los
mismos enriquecidos que el resto (título de cve.org, CWE, EPSS); las CWE del NVD sí se las
pierde, porque esas se piden por ventana de publicación y cve.org es la fuente principal.

Las fichas se guardan en `data/kev_extra.json` y la caché se poda con el catálogo: lo que
CISA o la EUVD retiran deja de publicarse aquí también.

El recuento de la cabecera lo dice separado ("N in the last 14 days + M older") y en el JSON
está `fueraDeVentana` con cuántas son. `totalEnEuvd` sigue siendo lo que la EUVD dice tener
en la ventana, sin lo sembrado: es con lo que se compara el aviso de paginación corta.

En Telegram, la primera pasada con catálogo **anota las ~1.300 sin avisar** y deja la marca
`sembradoKev` en `.notificado.json`. Sin eso, estrenar esto habría vaciado el catálogo entero
en la sala de KEV: más de una hora de mensajes sobre cosas explotadas desde hace años. A
partir de ahí sí llega lo que entre nuevo en el catálogo, que es el mismo trato que reciben
las salas recién montadas. Si el catálogo falla en esa pasada, la marca no se pone y la
siembra espera a la siguiente.

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
