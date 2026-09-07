# Feed de vulnerabilidades (EUVD)

Tabla web con las CVE publicadas recientemente: CVE, nombre, fabricante, CWE, criticidad,
EPSS y fecha. Fuentes: EU Vulnerability Database de ENISA para el listado, cve.org para el
título oficial y las CWE de cada CVE, el NVD del NIST para la puntuación CVSS, FIRST para
la EPSS y los catálogos CISA KEV / EU KEV para marcar lo que ya se está explotando.
Opcionalmente avisa por Telegram, con una sala por criticidad y otra para lo que ya se
está explotando; ver más abajo.

## Por qué no se llama a la API desde el navegador

Dos motivos. Uno, no se puede dar por hecho que la API envíe cabeceras CORS, así que un
`fetch()` desde el front puede morir en el navegador. Dos, `size` está limitado a 100 por
petición, así que "todas las últimas" implica paginar: eso no lo quieres haciendo cada
visitante, sino una vez por hora en el servidor.

El resultado: `euvd_sync.php` corre por cron, pagina la API y deja un JSON plano.
El React solo lee ese fichero. Rápido, sin rate limits, y la tabla sigue viva si la API se cae.

## Estructura en el hosting

```
public_html/
├── index.html          ← build de Vite
├── assets/
├── data/
│   ├── cves.json       ← lo escribe el cron
│   ├── cve_meta.json   ← caché de títulos y CWE de cve.org, también del cron
│   ├── scores_nvd.json ← caché de puntuaciones CVSS del NVD, ídem
│   └── epss.json       ← última EPSS conocida de FIRST, red por si la API cae
├── euvd_sync.php       ← mejor fuera de public_html si puedes
└── .notificado.json    ← qué se ha avisado ya por Telegram; junto al script, no en data/
```

## Montaje

1. **Front.** `npm create vite@latest -- --template react`, y usa
   `FeedVulnerabilidades.jsx` como componente en `App.jsx`. No necesita Tailwind ni
   dependencias: los estilos van embebidos.

2. **Sync.** Sube `euvd_sync.php` y ajusta `$destino` para que apunte a la carpeta
   `data/` del sitio publicado. Pruébalo a mano:

   ```bash
   php euvd_sync.php
   ```

3. **Cron** (hPanel → Avanzado → Trabajos cron), dos cadencias:

   ```
   */15 * * * * NVD_API_KEY=… /usr/bin/php ~/euvd_sync.php --rapido >> ~/logs/euvd.log 2>&1
   17 */6 * * * NVD_API_KEY=… /usr/bin/php ~/euvd_sync.php           >> ~/logs/euvd.log 2>&1
   ```

   Ver "Dos cadencias" más abajo. Ponle un `logrotate` o un truncado al log, que si
   no crece sin fin.

4. **Cabeceras.** En `.htaccess`, para que el JSON no se quede pegado en caché:

   ```apache
   <Files "cves.json">
     Header set Cache-Control "max-age=300, must-revalidate"
   </Files>
   ```

## Dos cadencias: pasada rápida y pasada completa

Las fuentes no cambian al mismo ritmo, así que el sync tiene dos modos. Medido sobre una
ventana de ~4.900 vulnerabilidades, con las cachés ya calientes:

| Fase | Completa | Rápida |
|---|---|---|
| Listado de la EUVD (50 páginas) | 35 s | 35 s |
| cve.org (solo las nuevas) | 1 s | 1 s |
| CVSS del NVD | **105 s** | de caché |
| EPSS de FIRST | 30 s | de caché |
| KEV | 1 s | 1 s |
| **Total** | **190 s** | **35 s** |

La pasada rápida (`--rapido`, o `SYNC_RAPIDO=1`) baja el listado, los títulos y CWE de lo
nuevo y el KEV, y lee de `scores_nvd.json` y `epss.json` en vez de preguntar. No se pierde
nada: las filas ya enriquecidas conservan su CVSS y su EPSS, y las recién aparecidas los
reciben en la siguiente pasada completa (hasta entonces salen como "Unscored" y "No data",
que es lo que ya hacían).

Merece la pena porque **el modelo EPSS se recalcula una vez al día** y el NVD tarda en
enriquecer: pedirlos cada quince minutos es bajar los mismos números. Lo único que trae
vulnerabilidades nuevas es el listado de la EUVD, y cuesta 35 s.

Cada 15 min la rápida y cada 6 h la completa deja las vulnerabilidades nuevas en la web en
un cuarto de hora en vez de en una, sin cuadruplicar el tráfico contra el NVD ni FIRST. El
JSON lleva un campo `modo` (`"rapido"` o `"completo"`) que dice cómo se generó.

## Un solo sync a la vez

Con el cron cada 15 minutos y pasadas completas de tres, dos ejecuciones solapadas se
pisarían las cachés y el rename atómico. Los dos scripts toman un cerrojo en `.sync.lock`
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

3. Pásale al cron el token y las salas que hayas montado, en las dos cadencias:

   ```
   0,15,30,45 * * * *  TELEGRAM_BOT_TOKEN=… TELEGRAM_CHAT_KEV=… TELEGRAM_CHAT_CRITICAS=… TELEGRAM_CHAT_ALTAS=… NVD_API_KEY=… /usr/bin/php ~/euvd_sync.php --rapido >> ~/logs/euvd.log 2>&1
   17 0,6,12,18 * * *  TELEGRAM_BOT_TOKEN=… TELEGRAM_CHAT_KEV=… TELEGRAM_CHAT_CRITICAS=… TELEGRAM_CHAT_ALTAS=… NVD_API_KEY=… /usr/bin/php ~/euvd_sync.php >> ~/logs/euvd.log 2>&1
   ```

   Si la línea se te hace inmanejable —o no quieres el token a la vista en el panel—, mete
   los `export` en un `~/euvd_env.sh` con `chmod 600` y llama a
   `. ~/euvd_env.sh && /usr/bin/php ~/euvd_sync.php --rapido`.

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

NVD · CVE Record
```

**Los mensajes van en inglés.** Es el idioma de las fuentes —el título sale de cve.org, las
CWE de MITRE, los catálogos de CISA y ENISA—, así que traducir el envoltorio dejaba cada
mensaje a medio idioma. Los logs y el código siguen en castellano.

Cuatro bloques: cabecera, título, la alerta de explotación si la hay, los datos y los
enlaces. La cabecera va primera porque es lo único que se lee en la notificación del móvil,
y el identificador va en monoespaciada para poder copiarlo de un toque, que es lo primero
que se hace con un CVE.

Cada dato se calla si no lo hay, que es mejor que una fila con un guion: el CVSS es el del
NVD y, si todavía no lo ha analizado, sale un `Score: EUVD, pending NVD analysis`; la EPSS
solo aparece si FIRST ya tiene dato —lo recién publicado no lo tiene, y un 0 sería mentir—;
el producto solo si difiere del fabricante; y los enlaces, solo si la fila tiene CVE.

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

### Cuando algo escala de sala

Una CVE que se avisó como alta y tres días después entra en KEV **se reavisa en la sala de
KEV**, con una primera línea que lo dice:

```
⬆️ Escalated — previously reported as High on 2026-09-04
```

Eso es lo que convierte la sala de KEV en algo útil: la mitad de lo que entra ahí son CVE de
las que ya se avisó hace días, y sin esa línea parecerían recién publicadas.

Solo se reavisa **hacia arriba** —a KEV, o de altas a críticas si el NVD sube la nota—.
Que el NVD rebaje una puntuación no genera mensaje: revisa notas a menudo y sería ruido.

### Nuevo no es reciente

Lo que decide si algo se avisa no es la fecha, es `.notificado.json`: un fichero con los
identificadores EUVD y **a qué sala fue cada uno**, junto al script y fuera de `data/`, que
es un directorio que se publica.

Tiene que ser así porque la ventana de 14 días se solapa entre pasadas y porque los datos
llegan tarde: una CVE entra hoy sin CVSS, sale como "Sin puntuar" y recibe su 9.8 tres
pasadas después. Filtrando por fecha, esa no se avisaría nunca; llevando la cuenta de lo
enviado y de dónde, se avisa el día que le toca y no se repite. El fichero se poda en cada
ejecución con las que siguen dentro de la ventana, igual que las demás cachés.

Las filas cuya sala no está montada **se anotan igual, sin enviarse**. Por eso el día que
añadas la sala de medias no te caen encima las 1.700 de la ventana: solo llega lo que
aparezca a partir de entonces. Y si vienes de la versión de un solo chat, el fichero de
estado se reconstruye solo en la primera pasada, también sin avisar.

### El ritmo

Como mucho salen `TG_MAX_MENSAJES` (12) avisos **por sala** y pasada, con una pausa de 1,2 s
entre mensajes: Telegram corta sobre 1 mensaje por segundo y chat, y responde 429 si te
pasas. El tope es por sala a propósito — un atasco en medias no debe retrasar el aviso de
una crítica. Lo que no quepa **no se pierde ni se marca**, sale en la pasada siguiente. Si
aun así llega un 429, el sync corta los envíos ahí y lo retoma en la siguiente.

La cola sale ordenada por sala y luego por puntuación, así que si un día hay atasco, lo que
ya se está explotando va delante.

Los avisos van **después** de escribir `cves.json` a propósito: que Telegram no conteste no
puede dejar la web sin actualizar. Todo lo que pasa —lo enviado por sala, lo encolado, los
errores— queda en el log del cron.

## Parámetros que querrás tocar

En `euvd_sync.php`:

- `VENTANA_DIAS` — días hacia atrás. 14 da un volumen manejable; 30 engorda bastante el JSON.
- `MAX_PAGINAS` — tope de seguridad. 60 páginas = 6.000 registros. **No lo bajes sin
  mirar el log**: si la ventana tiene más vulnerabilidades de las que caben, el sync avisa
  con un `AVISO:` y la web saca una banda, porque lo que se pierde no son las más antiguas
  sino las que la API no llegue a devolver. Con 14 días son ~5.000, así que 25 páginas se
  quedaban justo con la mitad.
- `PAUSA_US` — pausa entre peticiones. No lo bajes de 0,3 s.
- `CONCURRENCIA_TITULOS` — peticiones simultáneas a cve.org. 6 va sobrado; subirlo
  arriesga que te empiecen a devolver 429.
- `NVD_MARGEN_DIAS` — días extra de margen al pedir puntuaciones al NVD (ver más abajo).
- `EPSS_TANDA` — CVE por petición a FIRST. 100 es el máximo que admite la API.
- `NVD_API_KEY` — variable de entorno opcional. Sin ella el NVD deja 5 peticiones cada
  30 s; con ella, 50. Se pide gratis en <https://nvd.nist.gov/developers/request-an-api-key>
  y en el cron sería `0 * * * * NVD_API_KEY=… /usr/bin/php …`.

Con la ventana entera el JSON ronda los 6 MB, así que **sirve el `data/` con gzip**
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

La CVSS que se muestra es la del **NVD** (`baseScore` de la métrica más moderna que tenga:
v4.0, v3.1, v3.0 o v2, priorizando la primaria). La EUVD trae su propio `baseScore`, pero
es el que le pasa el CNA y no siempre coincide con el análisis del NIST.

No se pide CVE a CVE: la API del NVD admite 5 peticiones cada 30 s sin clave, así que 2.500
consultas serían horas. En vez de eso se baja **por rango de fechas de publicación**
(`pubStartDate`/`pubEndDate`, 2.000 por página), que resuelve la ventana entera en unos
segundos. El rango lleva `NVD_MARGEN_DIAS` de margen hacia atrás porque la fecha de
publicación del NVD no tiene por qué coincidir con la de la EUVD.

Cada fila lleva un campo `origenScore`:

- `"nvd"` — puntuación del NVD. Es el caso normal (~90 % de las filas).
- `"euvd"` — el NVD todavía no la ha analizado y se conserva la de la EUVD. La tabla lo
  marca con una etiqueta `EUVD` pequeña junto al número.
- `null` — nadie la ha puntuado: sale como "Sin puntuar".

Las puntuaciones se cachean en `data/scores_nvd.json` igual que los títulos, así que si el
NVD se cae o devuelve 503, la tabla sigue enseñando la última puntuación conocida.

## De dónde salen las CWE

La columna CWE es la debilidad de fondo: el *por qué* técnico de la vulnerabilidad
(CWE-79 XSS, CWE-78 inyección de comandos, CWE-787 escritura fuera de límites…), no su
gravedad. Sale de `containers.cna.problemTypes` del registro de cve.org, que se pide en la
misma llamada que el título, así que no cuesta ni una petición extra. También se leen los
contenedores ADP, que es donde CISA y los enriquecedores meten las suyas.

Cuando cve.org no trae ninguna, se cae al `weaknesses` del NVD, que ya viene en la misma
descarga por rango de fechas de las puntuaciones. Ahí solo está el identificador, sin el
nombre, así que la fila enseña "CWE-89" a secas.

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
  con datos escasos o en estado "Awaiting Analysis" — son justo las que se quedan con la
  puntuación de la EUVD. La alternativa es cve.org
  (`https://www.cve.org/CVERecord?id=CVE-…`). Se cambia en `normalizar()`.
- **Endpoints alternativos** por si más adelante quieres otras vistas:
  `/api/criticalvulnerabilities`, `/api/exploitedvulnerabilities` y `/api/kev/dump`
  (CISA KEV + EU KEV consolidados, actualizado a diario a las 07:00 UTC).
