/**
 * euvd_sync.mjs
 *
 * Equivalente en Node de euvd_sync.php, para desarrollo local en máquinas sin PHP.
 * Descarga las vulnerabilidades recientes de la EU Vulnerability Database (ENISA)
 * y las deja normalizadas en public/data/cves.json, que es lo que lee la web.
 *
 * En producción manda el .php por cron; esto solo es para verlo en local:
 *   npm run sync            pasada completa (~190 s)
 *   npm run sync -- --rapido   solo EUVD + cve.org + KEV (~40 s)
 *
 * Requiere Node 18+ (fetch nativo).
 */

import { mkdir, open, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { unlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------- configuración

const API_SEARCH = "https://euvdservices.enisa.europa.eu/api/search";
const API_CVE = "https://cveawg.mitre.org/api/cve/"; // registros oficiales de cve.org
const API_KEV = "https://euvdservices.enisa.europa.eu/api/kev/dump"; // CISA KEV + EU KEV
const API_ENISAID = "https://euvdservices.enisa.europa.eu/api/enisaid"; // ficha suelta, por id

// VulnCheck KEV: el mismo catálogo de explotación activa que el de la EUVD, pero
// más grande —5.200 entradas frente a 1.700, y ninguna de la EUVD falta aquí— y
// por delante: CISA suele confirmar uno o dos días después. Es la fuente que
// decide qué llega a Telegram; ver notificarTelegram(). Sin token el sync corre
// igual: la web sale como siempre, con la marca de CISA y EU KEV, y Telegram
// no manda nada, que es lo correcto — sin catálogo no se sabe qué avisar.
const API_VULNCHECK_KEV = "https://api.vulncheck.com/v3/index/vulncheck-kev";
// El NVD servido por VulnCheck. El catálogo de KEV trae el nombre, el fabricante,
// el producto y las CWE, pero no la puntuación ni la fecha de publicación, y el
// mensaje de Telegram las lleva. Se pide por CVE y solo de lo que se va a mandar
// —unos pocos por pasada—, así que no hace falta ni paginar ni cachear en disco.
const API_VULNCHECK_NVD = "https://api.vulncheck.com/v3/index/nist-nvd2";
const VULNCHECK_TOKEN = process.env.VULNCHECK_API_TOKEN ?? "";
const VULNCHECK_PAGE = 1000; // el máximo que sirve de una vez
// El tier community corta la paginación en 6 páginas: 6.000 entradas, de sobra
// para las 5.200 de hoy pero no para siempre. pedirVulncheckKev() avisa en el
// log en cuanto el catálogo no quepa, porque a partir de ahí el filtro de
// Telegram se dejaría fuera lo que no haya bajado.
const VULNCHECK_MAX_PAGINAS = 6;
const VENTANA_DIAS = 14; // cuántos días hacia atrás pedir
const PAGE_SIZE = 100; // máximo que admite la API
// La ventana de 14 días ronda las 6.000 vulnerabilidades, así que 25 páginas se
// quedaban con la mitad —y no con la mitad más reciente, sino con las que
// devolviera la API—. El tope sigue existiendo por seguridad, pero ahora holgado.
//
// A 60 se volvió a quedar corto el 2026-09-08: la EUVD decía 6.039 y bajaban
// 6.000. Y una descarga corta no es solo una web incompleta: lo que falta hoy
// entra mañana como si acabara de salir, que fue justo lo que llenó la cola de
// Telegram con 900 avisos de vulnerabilidades de hasta dos semanas.
const MAX_PAGINAS = 100; // tope de seguridad: 100 * 100 = 10.000 registros

// Cuánto se guarda una entrada en el registro después de dejar de aparecer. No es
// la caducidad del feed —esa son VENTANA_DIAS desde que se vio— sino la memoria de
// "esto ya lo conocía": si se olvidara antes de que la EUVD deje de devolverla,
// la pasada siguiente la tomaría por nueva y volvería a ingerirla.
const VISTAS_OLVIDO_DIAS = 14;

// Cuánto hacia atrás se siembra lo que solo consta en VulnCheck. Son ~3.500 CVE
// que la EUVD no marca, casi todas de hace años: pedir sus fichas una a una son
// veinte minutos por pasada y triplicar la tabla con cosas que no son noticia.
// Lo que hace falta es lo que acaba de entrar en el catálogo, que es lo único
// que esNoticia() deja avisar; la ventana del feed da margen sobre esos 7 días.
const VULNCHECK_SIEMBRA_DIAS = VENTANA_DIAS;
const PAUSA_MS = 400; // 0,4 s entre peticiones, para no castigar la API
const TIMEOUT_MS = 30000;
const CONCURRENCIA_TITULOS = 6; // peticiones simultáneas a cve.org

const API_EPSS = "https://api.first.org/data/v1/epss"; // probabilidad de explotación (FIRST)
const EPSS_TANDA = 100; // máximo de CVE que admite una petición a FIRST
const EPSS_PAUSA_MS = 300;

// Del NVD solo se sacan las CWE. La puntuación se dejó de coger: el NIST
// reanaliza por su cuenta y a veces no encajaba con la ficha de la EUVD —otra
// versión del CVSS, otro alcance—, así que el score tiene una sola fuente.
const API_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CLAVE = process.env.NVD_API_KEY ?? ""; // opcional: sube el límite a 50 peticiones/30 s
const NVD_PAGE = 2000; // máximo que admite la API del NVD
const NVD_MAX_PAGINAS = 15; // tope de seguridad: 15 * 2.000 = 30.000 CVE
const NVD_MARGEN_DIAS = 30; // se pide más ventana de la necesaria; ver completarCwesNvd()
const NVD_PAUSA_MS = NVD_CLAVE ? 1000 : 6500; // sin clave: 5 peticiones cada 30 s

// ---- Telegram. Sin token ni ningún chat, el sync corre igual y no avisa.
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN ?? "";

// Una sala por criticidad, más la de lo que ya se está explotando. Cada
// vulnerabilidad va solo a la suya, y la sala que no tenga chat no recibe nada:
// así se silencia el ruido sin perder las que importan. Ver salaDe() y destinoDe().
//
// El valor es un chat ("-1001234567890") o un tema de un grupo con foro
// ("-1001234567890:7"), que permite tener todas las salas en un solo grupo.
const TG_SALAS = {
  kev: process.env.TELEGRAM_CHAT_KEV ?? "", // explotándose ya (CISA KEV / EU KEV)
  critica: process.env.TELEGRAM_CHAT_CRITICAS ?? "", // CVSS >= 9.0
  alta: process.env.TELEGRAM_CHAT_ALTAS ?? "", // 7.0 - 8.9
  media: process.env.TELEGRAM_CHAT_MEDIAS ?? "", // 4.0 - 6.9
  baja: process.env.TELEGRAM_CHAT_BAJAS ?? "", // < 4.0
  sin_puntuar: process.env.TELEGRAM_CHAT_SIN_PUNTUAR ?? "", // aún sin CVSS de nadie
};

// Respaldo para las salas sin chat propio, que es el montaje de un solo grupo.
const TG_CHAT = process.env.TELEGRAM_CHAT_ID ?? "";
const TG_UMBRAL = Number(process.env.TELEGRAM_UMBRAL ?? "7"); // solo filtra lo que cae en el respaldo

// El freno de mano. Con la pausa puesta la pasada sigue haciendo todo lo demás
// —descargar, enriquecer y publicar la web— pero no manda, no edita y no borra
// nada en Telegram: se limita a anotar en silencio lo que va saliendo, igual que
// una siembra. Es a propósito que no encole: una pausa que guarda todo lo que no
// mandó es una bomba de relojería, y al quitarla saldrían de golpe los avisos de
// los días que estuvo parada.
const TG_EN_PAUSA = /^(1|si|sí|true|on)$/i.test(process.env.TELEGRAM_PAUSA ?? "");

const TG_MAX_MENSAJES = 12; // por sala y pasada; lo que sobre se avisa en la siguiente
// Las ediciones son silenciosas, así que pueden esperar: este tope existe solo
// para que una tanda de puestas al día no se coma la pasada entera a 3,5 s cada
// una. Lo que no entre se edita en la siguiente.
const TG_MAX_EDICIONES = 40; // por pasada, sumando todas las salas

// Cuánto puede llevar una fila en el catálogo de KEV para que su primer aviso
// siga siendo una noticia. La ventana ya filtra por fecha de publicación, pero
// el catálogo mete ~1.300 CVE explotadas de las que casi todas son de hace años.
// Ver esNoticia().
const TG_DIAS_NOTICIA = 7;

// Cuánto se recuerda una fila que ha dejado de aparecer. Antes se olvidaba en
// cuanto faltaba de una pasada, y eso convertía cualquier tropiezo de la API en
// un reaviso masivo: una página de la EUVD que falla o un catálogo de KEV que no
// baja dejan la lista a medias, se borran esos apuntes, y a la pasada siguiente
// vuelven las filas sin nada anotado y se avisan como si fueran nuevas. Una
// ventana entera de margen: el fichero no llega al doble y hacen falta dos
// semanas de fallos seguidos para perder un apunte que aún importa.
const TG_OLVIDO_DIAS = 14;

// El límite que manda no es el del chat sino el del grupo: unos 20 mensajes por
// minuto. Con las seis salas montadas como temas de un mismo grupo, los 1,2 s de
// antes iban a ~50/min contra ese tope y Telegram devolvía 429 (visto el
// 2026-09-08 a las 04:35). 3,5 s deja el ritmo en ~17/min, por debajo del límite.
const TG_PAUSA_MS = 3500;

/**
 * Modo rápido: el listado de la EUVD, los títulos y CWE nuevos de cve.org y el
 * KEV; las CWE del NVD y la EPSS se leen de la caché en vez de pedirse.
 *
 * Tiene sentido porque las fuentes no cambian al mismo ritmo: el modelo EPSS se
 * recalcula una vez al día y el NVD tarda en enriquecer, mientras que lo único
 * que trae vulnerabilidades nuevas es el listado. Así se puede pasar cada 15
 * minutos por 40 s en vez de por 190 s, y dejar la pasada completa cada 6 horas.
 */
const RAPIDO = process.argv.includes("--rapido") || process.env.SYNC_RAPIDO === "1";

const LOCK_CADUCIDAD_MS = 30 * 60000; // un sync que lleve media hora está muerto

const AQUI = dirname(fileURLToPath(import.meta.url));
const cerrojoRuta = join(AQUI, ".sync.lock");
const destino = join(AQUI, "public", "data", "cves.json");
const cacheMeta = join(AQUI, "public", "data", "cve_meta.json"); // título y CWE de cve.org
const cacheCwes = join(AQUI, "public", "data", "cwes_nvd.json");
const cacheEpss = join(AQUI, "public", "data", "epss.json");
// Las fichas de lo explotado que cae fuera de la ventana. Sin esta caché habría
// que volver a pedir ~1.300 fichas sueltas en cada pasada; con ella solo se piden
// las que entren nuevas en el catálogo, que son unas pocas por semana.
const cacheKev = join(AQUI, "public", "data", "kev_extra.json");
// Fuera de data/: ese directorio se publica y esto es estado interno, no un dato del feed.
const estadoTelegram = join(AQUI, ".notificado.json");
// La memoria del feed: qué entradas ha visto ya y cuándo vio cada una por primera
// vez. También fuera de data/, por lo mismo: es estado interno, no un dato.
const registroVistas = join(AQUI, ".vistas.json");

// ---------------------------------------------------------------- utilidades

const log = (msg) =>
  process.stdout.write(`[${new Date().toISOString().replace(/\.\d+Z$/, "Z")}] ${msg}\n`);

const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

const soloFecha = (d) => d.toISOString().slice(0, 10);

/** Escritura atómica: primero temporal, luego rename, para no servir un JSON a medias. */
async function escribirJson(ruta, datos) {
  await mkdir(dirname(ruta), { recursive: true });
  const temporal = ruta + ".tmp";
  await writeFile(temporal, JSON.stringify(datos), "utf8");
  await rename(temporal, ruta);
}

async function pedir(url, cabeceras = {}) {
  try {
    const r = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "euvd-feed/1.0", ...cabeceras },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!r.ok) {
      log(`HTTP ${r.status} en ${url}`);
      return null;
    }
    const json = await r.json();
    return json && typeof json === "object" ? json : null;
  } catch (e) {
    log(`Petición fallida: ${e.message}`);
    return null;
  }
}

/**
 * La API devuelve fechas tipo "Apr 15, 2025, 8:30:58 PM".
 * Las pasamos a ISO 8601 para poder ordenar y formatear sin sorpresas.
 */
function fechaIso(bruta) {
  if (typeof bruta !== "string" || bruta.trim() === "") return null;
  const d = new Date(bruta.replace(/,/g, ""));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function severidad(score) {
  if (score == null || score <= 0) return "sin_puntuar";
  if (score >= 9.0) return "critica";
  if (score >= 7.0) return "alta";
  if (score >= 4.0) return "media";
  return "baja";
}

/** El CVE viene dentro de `aliases`, separado por saltos de línea. */
function extraerCve(aliases) {
  if (typeof aliases !== "string") return null;
  const m = aliases.match(/CVE-\d{4}-\d{4,}/);
  return m ? m[0] : null;
}

function nombres(lista, clave) {
  if (!Array.isArray(lista)) return [];
  const salida = lista
    .map((e) => e?.[clave]?.name)
    .filter((n) => typeof n === "string" && n.trim() !== "")
    .map((n) => n.trim());
  return [...new Set(salida)];
}

/** Respaldo cuando cve.org no da título: primera frase de la descripción, recortada. */
function nombreCorto(descripcion) {
  const texto = descripcion.replace(/\s+/g, " ").trim();
  if (texto === "") return "Sin descripción";

  let frase = texto.split(/(?<=[.;])\s/, 1)[0] ?? texto;
  if ([...frase].length > 140) frase = [...frase].slice(0, 137).join("") + "…";
  return frase;
}

/**
 * Normaliza una debilidad a { id: "CWE-79", nombre: "Improper Neutralization…" }.
 * El id puede venir en su propio campo (`cweId` en cve.org) o solo como prefijo
 * del texto. Lo que no lleve número —"n/a", "Other", los NVD-CWE-noinfo— se
 * descarta: un hueco es más honesto que una etiqueta que no dice nada.
 */
function normalizarCwe(id, descripcion) {
  const texto = typeof descripcion === "string" ? descripcion.trim() : "";
  let clave = typeof id === "string" ? id.trim() : "";

  if (!/^CWE-\d+$/.test(clave)) {
    const m = texto.match(/^CWE-(\d+)/);
    clave = m ? `CWE-${m[1]}` : "";
  }
  if (clave === "") return null;

  let nombre = texto.replace(/^CWE-\d+[\s:.-]*/, "").trim();
  if (nombre === "" || /^(n\/a|other|unknown)$/i.test(nombre)) nombre = null;

  return { id: clave, nombre };
}

/** Une varias listas de CWE quitando repetidos y quedándose con la que trae nombre. */
function fusionarCwes(...listas) {
  const mapa = new Map();
  for (const cwe of listas.flat()) {
    if (!cwe) continue;
    const previo = mapa.get(cwe.id);
    if (!previo || (!previo.nombre && cwe.nombre)) mapa.set(cwe.id, cwe);
  }
  return [...mapa.values()];
}

/** Las CWE del registro CVE 5.x, tanto del CNA como de los enriquecedores (ADP). */
function cwesDeCveOrg(json) {
  const contenedores = [json?.containers?.cna, ...(json?.containers?.adp ?? [])];
  const salida = [];

  for (const contenedor of contenedores) {
    for (const tipo of contenedor?.problemTypes ?? []) {
      for (const d of tipo?.descriptions ?? []) {
        if (d?.type && d.type !== "CWE") continue;
        salida.push(normalizarCwe(d?.cweId, d?.description));
      }
    }
  }
  return fusionarCwes(salida);
}

/**
 * Registro oficial de cve.org: título (`containers.cna.title`) y CWE asignadas.
 * El título es opcional en el esquema CVE 5.x, así que puede no venir; y un CVE
 * recién reservado devuelve 404 aunque la EUVD ya lo liste. En ambos casos, null.
 */
async function pedirRegistroCve(cve) {
  try {
    const r = await fetch(API_CVE + cve, {
      headers: { Accept: "application/json", "User-Agent": "euvd-feed/1.0" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!r.ok) return null;

    const json = await r.json();
    const titulo = json?.containers?.cna?.title;
    return {
      titulo: typeof titulo === "string" && titulo.trim() !== "" ? titulo.trim() : null,
      cwes: cwesDeCveOrg(json),
    };
  } catch {
    return null;
  }
}

async function leerCache(ruta) {
  try {
    const json = JSON.parse(await readFile(ruta, "utf8"));
    return json && typeof json === "object" ? json : {};
  } catch {
    return {}; // primera ejecución, o caché corrupta: se rehace sola
  }
}

/**
 * Pone en `nombre` el título de cve.org y en `cwes` las debilidades del registro.
 * Solo pedimos los CVE que no estén ya en caché: la ventana se solapa entre
 * ejecuciones y no tiene sentido bajar 2.500 registros cada hora. Los fallos de
 * red no se cachean, así se reintentan en la pasada siguiente.
 */
async function completarMeta(filas) {
  const cache = await leerCache(cacheMeta);
  const pendientes = [
    ...new Set(filas.map((f) => f.cve).filter((c) => c && !(c in cache))),
  ];

  log(`cve.org: ${Object.keys(cache).length} registros en caché, ${pendientes.length} por pedir`);

  let siguiente = 0;
  let hechos = 0;
  const obrero = async () => {
    while (siguiente < pendientes.length) {
      const cve = pendientes[siguiente++];
      const registro = await pedirRegistroCve(cve);
      if (registro) cache[cve] = registro;
      if (++hechos % 100 === 0) log(`  ${hechos}/${pendientes.length} registros de cve.org`);
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCIA_TITULOS }, obrero));

  // Los que no tengan título se quedan con la primera frase de la descripción.
  const vigentes = {};
  let conTitulo = 0;
  let conCwe = 0;
  for (const fila of filas) {
    const registro = fila.cve ? cache[fila.cve] : null;
    if (!registro) continue;

    if (registro.titulo) {
      fila.nombre = registro.titulo;
      conTitulo++;
    }
    if (registro.cwes?.length) {
      fila.cwes = fusionarCwes(registro.cwes);
      conCwe++;
    }
    vigentes[fila.cve] = registro;
  }

  // Reescribimos la caché solo con lo que sigue en ventana: si no, crece sin fin.
  await escribirJson(cacheMeta, vigentes);
  log(`${conTitulo} de ${filas.length} filas con título de cve.org, ${conCwe} con CWE`);
}

// ---------------------------------------------------------------- CWE del NVD

const fechaNvd = (d) => d.toISOString().slice(0, 19) + ".000";

/** Las CWE que el NVD asigna a una CVE. Vienen sin nombre, solo el identificador. */
function cwesDeNvd(weaknesses) {
  const salida = [];
  for (const debilidad of weaknesses ?? []) {
    for (const d of debilidad?.description ?? []) {
      salida.push(normalizarCwe(d?.value, null));
    }
  }
  return fusionarCwes(salida);
}

/**
 * Baja del NVD las CWE de todas las CVE publicadas en un rango de fechas, paginando.
 * @returns {Promise<Record<string, {id:string,nombre:string|null}[]>>}
 */
async function pedirCwesNvd(desdeIso, hastaIso) {
  const cabeceras = NVD_CLAVE ? { apiKey: NVD_CLAVE } : {};
  const salida = {};

  for (let pagina = 0; pagina < NVD_MAX_PAGINAS; pagina++) {
    const url =
      API_NVD +
      "?" +
      new URLSearchParams({
        pubStartDate: desdeIso,
        pubEndDate: hastaIso,
        resultsPerPage: String(NVD_PAGE),
        startIndex: String(pagina * NVD_PAGE),
      });

    const respuesta = await pedir(url, cabeceras);
    if (respuesta === null) {
      log("El NVD falló; me quedo con las CWE que ya tenga.");
      break;
    }

    const vulns = respuesta.vulnerabilities ?? [];
    if (!Array.isArray(vulns) || vulns.length === 0) break;

    for (const entrada of vulns) {
      const id = entrada?.cve?.id;
      if (typeof id !== "string") continue;

      const cwes = cwesDeNvd(entrada?.cve?.weaknesses);
      if (cwes.length) salida[id] = cwes;
    }

    const total = respuesta.totalResults ?? 0;
    log(`NVD página ${pagina}: ${vulns.length} CVE (con CWE acumuladas: ${Object.keys(salida).length})`);

    if ((pagina + 1) * NVD_PAGE >= total) break;
    await dormir(NVD_PAUSA_MS);
  }

  return salida;
}

/**
 * Completa con el NVD las CWE que cve.org no haya dado.
 *
 * La puntuación no se toca: el CVSS sale siempre de la EUVD. Antes se pisaba con
 * el del NVD y a veces no encajaba —el NIST reanaliza por su cuenta, con otra
 * versión del CVSS o sobre otro alcance—, y la fila acababa enseñando un número
 * que no era el de la ficha que describe.
 *
 * Se pide por rango de fechas en vez de CVE a CVE porque la API del NVD admite
 * 5 peticiones cada 30 s sin clave (50 con `NVD_API_KEY`): así son ~9 páginas para
 * la ventana entera, mientras que ir uno por uno serían horas. El rango va con
 * NVD_MARGEN_DIAS de margen hacia atrás porque la fecha de publicación en el NVD
 * no tiene por qué coincidir con la de la EUVD.
 */
async function completarCwesNvd(filas) {
  const hasta = new Date();
  const desde = new Date(hasta.getTime() - (VENTANA_DIAS + NVD_MARGEN_DIAS) * 86400000);

  const cache = await leerCache(cacheCwes);
  // En modo rápido no se pregunta al NVD: es la fase más lenta con diferencia y
  // el enriquecimiento no va a cambiar en quince minutos.
  const frescas = RAPIDO ? {} : await pedirCwesNvd(fechaNvd(desde), fechaNvd(hasta));
  const porCve = { ...cache, ...frescas }; // lo recién bajado manda sobre la caché

  const vigentes = {};
  let conNvd = 0;
  for (const fila of filas) {
    const cwes = fila.cve ? porCve[fila.cve] : null;
    if (!cwes?.length) continue;

    // El NVD solo completa las CWE que cve.org no haya dado: allí vienen con nombre.
    fila.cwes = fusionarCwes(fila.cwes, cwes);
    vigentes[fila.cve] = cwes;
    conNvd++;
  }

  // Igual que con los títulos: la caché se queda solo con lo que sigue en ventana.
  await escribirJson(cacheCwes, vigentes);
  log(`${conNvd} de ${filas.length} filas con CWE del NVD${RAPIDO ? " (de caché)" : ""}`);
}

// ---------------------------------------------------------------- EPSS de FIRST

/**
 * Probabilidad de que una CVE se explote en los próximos 30 días, según el modelo
 * EPSS de FIRST. Se pide en tandas de 100 porque es lo que admite la API por
 * petición; una CVE recién publicada aún no tiene puntuación y no vuelve en la
 * respuesta.
 *
 * @returns {Promise<Record<string, {epss:number,percentil:number|null,fecha:string|null}>>}
 */
async function pedirEpss(cves) {
  const salida = {};

  for (let i = 0; i < cves.length; i += EPSS_TANDA) {
    const tanda = cves.slice(i, i + EPSS_TANDA);
    const url =
      API_EPSS + "?" + new URLSearchParams({ cve: tanda.join(","), limit: String(EPSS_TANDA) });

    const respuesta = await pedir(url);
    if (respuesta === null) {
      log("FIRST falló; me quedo con las puntuaciones EPSS que ya tenga.");
      break;
    }

    for (const entrada of respuesta.data ?? []) {
      const puntuacion = Number(entrada?.epss);
      if (typeof entrada?.cve !== "string" || !Number.isFinite(puntuacion)) continue;

      const percentil = Number(entrada?.percentile);
      salida[entrada.cve] = {
        epss: puntuacion,
        percentil: Number.isFinite(percentil) ? percentil : null,
        fecha: typeof entrada?.date === "string" ? entrada.date : null,
      };
    }

    log(`EPSS ${Math.min(i + EPSS_TANDA, cves.length)}/${cves.length} (con puntuación: ${Object.keys(salida).length})`);
    if (i + EPSS_TANDA < cves.length) await dormir(EPSS_PAUSA_MS);
  }

  return salida;
}

/**
 * Pone la EPSS oficial de FIRST en cada fila.
 *
 * La EUVD trae un campo `epss`, pero llega en porcentaje y vale 0 en todo lo
 * recién publicado, que es justo lo que enseña este feed: por eso se pide a la
 * fuente. Aquí no vale cachear y no volver a preguntar como con los títulos —el
 * modelo se recalcula a diario—, así que se piden todas y la caché solo sirve de
 * red por si FIRST no responde.
 */
async function completarEpss(filas) {
  const cache = await leerCache(cacheEpss);
  const cves = [...new Set(filas.map((f) => f.cve).filter(Boolean))];

  // En modo rápido tiramos de caché: el modelo de FIRST se publica una vez al día,
  // así que preguntarlo cada quince minutos es bajar los mismos números.
  log(RAPIDO ? "EPSS: uso la caché, no pregunto a FIRST" : `EPSS: ${cves.length} CVE por consultar a FIRST`);
  const frescas = RAPIDO ? {} : await pedirEpss(cves);
  const epss = { ...cache, ...frescas }; // lo recién bajado manda sobre la caché

  const vigentes = {};
  let conEpss = 0;
  for (const fila of filas) {
    const dato = fila.cve ? epss[fila.cve] : null;
    if (!dato) continue;

    fila.epss = dato.epss;
    fila.epssPercentil = dato.percentil ?? null;
    fila.epssFecha = dato.fecha ?? null;
    fila.origenEpss = "first";
    vigentes[fila.cve] = dato;
    conEpss++;
  }

  await escribirJson(cacheEpss, vigentes);
  log(`${conEpss} de ${filas.length} filas con EPSS de FIRST${RAPIDO ? " (de caché)" : ""}`);
}

// ---------------------------------------------------------------- KEV

/**
 * El catálogo de lo que ya se está explotando: CISA KEV y EU KEV, que la EUVD
 * consolida y sirve de una vez en `/api/kev/dump`. Una sola petición, sin paginar.
 *
 * Es el complemento de la EPSS, no un duplicado: la EPSS estima la probabilidad
 * de que alguien la explote, el KEV dice que ya lo está haciendo. Y no se parecen
 * —de las que caen en KEV, la mayoría anda por debajo del 1 % de EPSS—, así que
 * ordenar por EPSS las entierra.
 *
 * Se pide una vez por pasada y el resultado lo usan sembrarKev() y completarKev().
 */
async function pedirKev() {
  const dump = await pedir(API_KEV);
  const entradas = Array.isArray(dump) ? dump : dump?.items;

  if (!Array.isArray(entradas)) {
    log("KEV: no pude leer el catálogo.");
    return null;
  }
  return entradas;
}

/**
 * El catálogo de VulnCheck KEV, como un mapa de CVE a su ficha.
 *
 * Se pagina porque no cabe de una vez, y una descarga a medias no vale: este
 * catálogo no solo marca filas, decide qué sale por Telegram y con qué texto, así
 * que media lista son avisos que no se mandan. Si falla una página se devuelve
 * null y la pasada se queda sin avisar; en diez minutos hay otra.
 *
 * Se guarda la ficha entera y no solo la fecha porque de aquí sale el mensaje:
 * ver mensajeTelegram(). Las fechas van en YYYY-MM-DD, como las de la EUVD, para
 * que las dos se puedan comparar.
 */
async function pedirVulncheckKev() {
  if (!VULNCHECK_TOKEN) {
    log("VulnCheck: sin VULNCHECK_API_TOKEN, no pido el catálogo.");
    return null;
  }

  const porCve = new Map();
  let total = null;

  for (let pagina = 1; pagina <= VULNCHECK_MAX_PAGINAS; pagina++) {
    const url =
      API_VULNCHECK_KEV +
      "?" +
      new URLSearchParams({ limit: String(VULNCHECK_PAGE), page: String(pagina) });
    const respuesta = await pedir(url, { Authorization: `Bearer ${VULNCHECK_TOKEN}` });

    if (respuesta === null) {
      log(`VulnCheck: falló la página ${pagina}; me quedo sin catálogo esta pasada.`);
      return null;
    }

    const datos = Array.isArray(respuesta.data) ? respuesta.data : [];
    if (total === null) total = Number(respuesta?._meta?.total_documents ?? NaN);

    for (const e of datos) {
      const ficha = fichaVulncheck(e);
      for (const cve of Array.isArray(e?.cve) ? e.cve : []) {
        if (typeof cve !== "string" || cve === "") continue;
        // Si un CVE aparece dos veces manda la ficha más antigua: lo que importa
        // es desde cuándo consta explotado, que es lo que mira esNoticia().
        const previa = porCve.get(cve);
        if (previa?.fecha && (!ficha.fecha || previa.fecha <= ficha.fecha)) continue;
        porCve.set(cve, ficha);
      }
    }

    if (datos.length < VULNCHECK_PAGE) break;
    await dormir(PAUSA_MS);
  }

  if (Number.isFinite(total) && total > VULNCHECK_MAX_PAGINAS * VULNCHECK_PAGE) {
    log(
      `VulnCheck: el catálogo tiene ${total} entradas y el tier community solo deja ` +
        `bajar ${VULNCHECK_MAX_PAGINAS * VULNCHECK_PAGE}. Falta parte, y lo que falte no se avisa.`
    );
  }

  log(`VulnCheck KEV: ${porCve.size} CVE explotadas en el catálogo`);
  return porCve;
}

/**
 * Una entrada del catálogo, con los nombres del feed. Es lo que acaba en el
 * mensaje de Telegram, así que se queda con todo lo que el catálogo sabe y el
 * resto de fuentes no: si CISA lo confirmó también y cuándo, si hay campañas de
 * ransomware usándola, el plazo de parcheo y las pruebas de explotación.
 */
function fichaVulncheck(e) {
  const soloDia = (v) => (typeof v === "string" && v !== "" ? v.slice(0, 10) : null);
  const evidencias = (Array.isArray(e?.vulncheck_reported_exploitation) ? e.vulncheck_reported_exploitation : [])
    .map((r) => r?.url)
    .filter((u) => typeof u === "string" && /^https?:\/\//.test(u));

  return {
    fecha: soloDia(e?.date_added),
    cisaFecha: soloDia(e?.cisa_date_added),
    plazo: soloDia(e?.dueDate),
    nombre: typeof e?.vulnerabilityName === "string" ? e.vulnerabilityName.trim() : "",
    descripcion: typeof e?.shortDescription === "string" ? e.shortDescription.trim() : "",
    accion: typeof e?.required_action === "string" ? e.required_action.trim() : "",
    vendor: typeof e?.vendorProject === "string" ? e.vendorProject.trim() : "",
    producto: typeof e?.product === "string" ? e.product.trim() : "",
    cwes: (Array.isArray(e?.cwes) ? e.cwes : []).filter((c) => /^CWE-\d+$/.test(c)),
    ransomware: e?.knownRansomwareCampaignUse === "Known",
    canarios: e?.reported_exploited_by_vulncheck_canaries === true,
    evidencias: [...new Set(evidencias)],
  };
}

/**
 * La puntuación, el vector, las CWE y la fecha de publicación de un CVE, del NVD
 * que sirve el propio VulnCheck. Es lo único del mensaje que el catálogo de KEV
 * no trae, y se pide de una en una porque solo hace falta para lo que se manda:
 * con el filtro puesto son unos pocos por pasada, muy lejos de las 1.000
 * peticiones por minuto que deja el tier community.
 */
async function pedirVulncheckNvd(cve) {
  const url = API_VULNCHECK_NVD + "?" + new URLSearchParams({ cve });
  const respuesta = await pedir(url, { Authorization: `Bearer ${VULNCHECK_TOKEN}` });
  const ficha = Array.isArray(respuesta?.data) ? respuesta.data[0] : null;
  if (!ficha) return null;

  // De las métricas manda la versión más alta que traiga, y a igualdad la del
  // asignador: es el mismo criterio con el que el NVD enseña una sola.
  let mejor = null;
  for (const [clave, lista] of Object.entries(ficha.metrics ?? {})) {
    if (!clave.startsWith("cvssMetric") || !Array.isArray(lista)) continue;
    for (const m of lista) {
      const d = m?.cvssData;
      const score = Number(d?.baseScore);
      if (!Number.isFinite(score)) continue;

      const version = Number.parseFloat(d.version ?? "0") || 0;
      const primaria = m?.type === "Primary";
      if (mejor && !(version > mejor.version || (version === mejor.version && primaria && !mejor.primaria))) continue;

      // Los dos subíndices cuelgan de la métrica, no de cvssData, y se cogen de
      // la misma que da el score: mezclarlos con los de otra sería sumar peras
      // y manzanas. El CVSS 4.0 no los tiene, así que ahí se quedan en null.
      mejor = {
        version,
        primaria,
        score,
        vector: typeof d.vectorString === "string" ? d.vectorString : null,
        explotabilidad: Number.isFinite(Number(m?.exploitabilityScore)) ? Number(m.exploitabilityScore) : null,
        impacto: Number.isFinite(Number(m?.impactScore)) ? Number(m.impactScore) : null,
      };
    }
  }

  const cwes = (Array.isArray(ficha.weaknesses) ? ficha.weaknesses : [])
    .flatMap((w) => (Array.isArray(w?.description) ? w.description : []))
    .map((d) => d?.value)
    .filter((v) => typeof v === "string" && /^CWE-\d+$/.test(v));

  return {
    score: mejor?.score ?? null,
    cvss: mejor ? String(mejor.version) : null,
    vector: mejor?.vector ?? null,
    explotabilidad: mejor?.explotabilidad ?? null,
    impacto: mejor?.impacto ?? null,
    // Sin recortar: el mensaje enseña también la hora. El NVD la publica en UTC
    // y sin marca horaria, que es justo por lo que el mensaje lo dice.
    publicado: typeof ficha.published === "string" ? ficha.published : null,
    cwes: [...new Set(cwes)],
  };
}

// Una sola petición por CVE y pasada: entre un envío y la edición del mismo
// mensaje no hace falta volver a preguntar.
const nvdVistas = new Map();

async function datosVulncheckNvd(cve) {
  if (typeof cve !== "string" || cve === "") return null;
  if (!nvdVistas.has(cve)) nvdVistas.set(cve, await pedirVulncheckNvd(cve));
  return nvdVistas.get(cve);
}

/**
 * Mete en el listado lo explotado que la ventana no alcanza.
 *
 * La búsqueda de la EUVD filtra por fecha de publicación, así que una CVE
 * publicada en abril y explotada desde mayo no sale por ningún lado: ni en la web
 * ni en la sala de KEV de Telegram, por muy grave que sea. Y eso es justo lo que
 * no puede faltar, que es el único motivo por el que este feed pesa lo que pesa.
 *
 * completarKev() no servía para esto porque solo marca lo ya descargado; aquí se
 * añaden filas, pidiendo la ficha suelta de cada una a `/api/enisaid`.
 *
 * El catálogo entero son ~1.300 entradas y casi ninguna cae en la ventana, así que
 * las fichas se guardan en su propia caché y solo se piden las que aún no estén.
 * En régimen son unas pocas por semana; la primera pasada sí paga las 1.300.
 *
 * La caché se poda con el catálogo, como las demás: lo que sale de KEV deja de
 * mantenerse y de publicarse, que es lo correcto —si CISA lo retira, aquí también.
 */
async function sembrarKev(registros, entradas, vulncheck) {
  if (!entradas && !vulncheck) {
    log("KEV: sin catálogo, no siembro nada fuera de ventana.");
    return;
  }

  const cache = await leerCache(cacheKev);

  // Lo que ya trajo la ventana no se vuelve a pedir, ni por su id de la EUVD ni
  // por su CVE: la ficha sería la misma y la de la ventana viene más fresca.
  const enVentana = new Set();
  for (const fila of registros.values()) {
    enVentana.add(fila.euvd);
    if (fila.cve) enVentana.add(fila.cve);
  }

  // La clave con la que se pide la ficha: el id de la EUVD para lo que trae su
  // catálogo y el CVE para lo que solo trae VulnCheck, que no da ids de la EUVD.
  // `/api/enisaid` acepta las dos cosas, así que a partir de aquí da igual de
  // dónde venga cada una.
  const faltan = [];
  const pedidas = new Set();
  for (const e of entradas ?? []) {
    const euvd = typeof e?.euvdId === "string" ? e.euvdId : null;
    if (!euvd || enVentana.has(euvd)) continue;
    if (typeof e?.cveId === "string" && enVentana.has(e.cveId)) continue;
    faltan.push(euvd);
    pedidas.add(euvd);
    if (typeof e?.cveId === "string") pedidas.add(e.cveId);
  }

  // De lo que solo tiene VulnCheck se siembra lo recién añadido y nada más; ver
  // VULNCHECK_SIEMBRA_DIAS. Sin esto, la mayoría de lo que VulnCheck marca antes
  // que CISA no llegaría a Telegram: son CVE de hace meses o años, no las alcanza
  // la ventana, y sin fila no hay aviso por muy explotadas que estén.
  const desdeSiembra = Date.now() - VULNCHECK_SIEMBRA_DIAS * 86400000;
  let deVulncheck = 0;
  for (const [cve, ficha] of vulncheck ?? []) {
    if (enVentana.has(cve) || pedidas.has(cve)) continue;
    const entrada = Date.parse(ficha?.fecha ?? "");
    if (Number.isNaN(entrada) || entrada < desdeSiembra) continue;
    faltan.push(cve);
    pedidas.add(cve);
    deVulncheck++;
  }

  const pendientes = faltan.filter((clave) => !(clave in cache));
  log(
    `KEV: ${faltan.length} explotadas fuera de la ventana ` +
      `(${deVulncheck} solo en VulnCheck), ` +
      `${faltan.length - pendientes.length} en caché, ${pendientes.length} por pedir`
  );

  let hechas = 0;
  for (const clave of pendientes) {
    const ficha = await pedir(API_ENISAID + "?" + new URLSearchParams({ id: clave }));
    const fila = ficha ? normalizar(ficha) : null;
    // Los fallos no se cachean: se reintentan en la pasada siguiente, igual que
    // en completarMeta(). Una ficha que no baja hoy baja dentro de diez minutos.
    if (fila) cache[clave] = fila;
    if (++hechas % 50 === 0) log(`  ${hechas}/${pendientes.length} fichas de la EUVD`);
    await dormir(PAUSA_MS);
  }

  // Poda: la caché se queda solo con lo que sigue en el catálogo.
  const vigentes = {};
  let sembradas = 0;
  for (const clave of faltan) {
    const fila = cache[clave];
    if (!fila) continue;

    vigentes[clave] = fila;
    // La marca es lo que distingue una fila traída por el catálogo de una traída
    // por la ventana. La usa notificarTelegram() para no vaciar el catálogo
    // entero en la sala de KEV la primera vez, y sale en el JSON porque es una
    // diferencia real: esta fila está aquí por estar explotada, no por reciente.
    registros.set(fila.euvd, { ...fila, fueraDeVentana: true });
    sembradas++;
  }

  await escribirJson(cacheKev, vigentes);
  log(`KEV: ${sembradas} filas añadidas fuera de la ventana`);
}

/** Marca con la fecha y las fuentes del catálogo las filas que están en él. */
function completarKev(filas, entradas, vulncheck) {
  if (!entradas && !vulncheck) {
    log("KEV: sin catálogo, las filas se quedan sin marcar.");
    return;
  }

  const porCve = new Map();
  const porEuvd = new Map();
  for (const e of entradas ?? []) {
    if (typeof e?.cveId === "string") porCve.set(e.cveId, e);
    if (typeof e?.euvdId === "string") porEuvd.set(e.euvdId, e);
  }

  let marcadas = 0;
  let conVulncheck = 0;
  for (const fila of filas) {
    const kev = (fila.cve && porCve.get(fila.cve)) || porEuvd.get(fila.euvd);
    // El catálogo de VulnCheck va por CVE: una fila sin CVE no se puede cruzar.
    const vc = fila.cve && vulncheck?.has(fila.cve) ? vulncheck.get(fila.cve) : undefined;
    if (!kev && vc === undefined) continue;

    const fuentes = Array.isArray(kev?.sources) ? [...kev.sources] : [];
    if (vc !== undefined) fuentes.push("vulncheck_kev");

    // De las dos fechas manda la más antigua: lo que importa es desde cuándo
    // consta explotada, no cuál de los dos catálogos se enteró el último. Es la
    // que mira esNoticia() para decidir si el primer aviso todavía es noticia.
    const fechas = [
      typeof kev?.dateAdded === "string" ? kev.dateAdded.slice(0, 10) : null,
      vc?.fecha ?? null,
    ].filter((f) => typeof f === "string" && f !== "");

    fila.kev = {
      fecha: fechas.length ? fechas.sort()[0] : null,
      fuentes,
    };
    marcadas++;
    if (vc !== undefined) conVulncheck++;
  }

  log(
    `${marcadas} de ${filas.length} filas explotadas activamente ` +
      `(${conVulncheck} confirmadas por VulnCheck, que es lo que llega a Telegram)`
  );
}

// ---------------------------------------------------------------- normalización

function normalizar(item) {
  const euvd = item?.id;
  if (typeof euvd !== "string") return null;

  const descripcion = String(item.description ?? "").trim();
  const score = item.baseScore != null ? Number(item.baseScore) : null;
  const vendors = nombres(item.enisaIdVendor, "vendor");
  const productos = nombres(item.enisaIdProduct, "product");
  const cve = extraerCve(item.aliases);

  // La EUVD manda la EPSS en porcentaje (1.55 = 1,55 %) y con 0 cuando no la
  // tiene. Aquí se guarda como probabilidad 0–1, que es como la publica FIRST;
  // completarEpss() la sustituye por la del modelo en cuanto exista.
  const epssEuvd = item.epss != null ? Number(item.epss) : null;

  return {
    euvd,
    cve,
    nombre: nombreCorto(descripcion), // lo pisa completarMeta() si cve.org tiene título
    descripcion,
    vendor: vendors[0] ?? null,
    vendors,
    producto: productos[0] ?? null,
    productos,
    // La EUVD manda 0 cuando no hay CVSS: eso no es una puntuación, es un hueco,
    // y severidad() lo deja en "sin_puntuar". Es la única fuente del score.
    score,
    severidad: severidad(score),
    cvss: item.baseScoreVersion ?? null,
    vector: item.baseScoreVector ?? null,
    cwes: [], // lo rellenan completarMeta() y completarCwesNvd()
    kev: null, // lo rellena completarKev()
    epss: epssEuvd != null && epssEuvd > 0 ? epssEuvd / 100 : null,
    epssPercentil: null, // solo lo da FIRST
    epssFecha: null,
    origenEpss: epssEuvd != null && epssEuvd > 0 ? "euvd" : null, // lo pisa completarEpss()
    assigner: item.assigner ?? null,
    fecha: fechaIso(item.datePublished),
    actualizado: fechaIso(item.dateUpdated),
    enlace: cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null,
  };
}

// ---------------------------------------------------------------- Telegram

/**
 * Las salas, de menos a más prioridad. Este orden decide a qué sala va una fila
 * que encaja en varias —KEV manda sobre la puntuación— y, cuando una fila cambia
 * de sala, si la mudanza es hacia arriba o hacia abajo, que es lo único que
 * distingue el encabezado de un mensaje del otro.
 */
const TG_ORDEN = ["sin_puntuar", "baja", "media", "alta", "critica", "kev"];


const prioridadSala = (sala) => TG_ORDEN.indexOf(sala);

/** Cada fila va a una sola sala: la de KEV si consta explotada, si no la de su severidad. */
const salaDe = (fila) => (fila.kev ? "kev" : fila.severidad);

/**
 * El filtro de Telegram: solo sale por el grupo lo que VulnCheck KEV da por
 * explotado. Todo lo demás sigue en la web —la tabla no cambia— pero no genera
 * mensajes, que es lo que se pidió: el grupo deja de ser un boletín de novedades
 * y pasa a ser la lista de lo que hay que parchear ya.
 *
 * Como todo lo que pasa este filtro tiene `kev`, salaDe() lo manda a la sala de
 * KEV: las salas por criticidad se quedan mudas mientras el filtro esté puesto.
 */
const esVulncheckKev = (fila) => (fila.kev?.fuentes ?? []).includes("vulncheck_kev");

/** La ficha del catálogo de VulnCheck de una fila, que es de donde sale su mensaje. */
const fichaDe = (fila, vulncheck) =>
  typeof fila.cve === "string" ? (vulncheck?.get(fila.cve) ?? null) : null;

/**
 * Si el primer aviso de una fila todavía es una noticia.
 *
 * Lo que trae la ventana lo es por definición: son catorce días de
 * publicaciones. Lo que trae el catálogo de KEV, no —la mayoría se explota desde
 * hace años—, y ahí lo único que es noticia es haber entrado en el catálogo hace
 * poco: una CVE de 2021 que CISA añade hoy sí importa, la misma CVE añadida en
 * 2022 no.
 *
 * Solo decide el primer aviso. Una fila ya anotada sigue su camino de siempre por
 * vieja que sea: si cambia se edita, y si cambia de sala se muda a la que toque.
 */
function esNoticia(fila, ahoraIso) {
  if (!fila.fueraDeVentana) return true;

  const entrada = Date.parse(fila.kev?.fecha ?? "");
  if (Number.isNaN(entrada)) return false;
  return Date.parse(ahoraIso) - entrada <= TG_DIAS_NOTICIA * 86400000;
}

// Las bandas de EPSS que cuentan como cambio. El modelo de FIRST se recalcula a
// diario y casi ninguna CVE conserva el mismo decimal de un día para otro: sin
// bandas habría que reeditar la ventana entera cada día, que son miles de
// llamadas contra un límite de veinte por minuto. Cruzar el 1, el 10 o el 50 %
// cambia lo que uno hace con una vulnerabilidad; el tercer decimal no.
const TG_BANDAS_EPSS = [0.01, 0.1, 0.5];

const bandaEpss = (v) => (typeof v === "number" ? TG_BANDAS_EPSS.filter((b) => v >= b).length : -1);

/**
 * Firma corta y estable; no hace falta resistencia a colisiones, hace falta que
 * euvd_sync.php calcule exactamente la misma. Por eso SHA-1 sobre los bytes UTF-8
 * y no algo hecho a mano: PHP recorre bytes y JavaScript unidades UTF-16, así que
 * cualquier hash artesanal se separaría en cuanto hubiera un acento.
 */
const firmaCorta = (texto) => createHash("sha1").update(texto, "utf8").digest("hex").slice(0, 10);

/**
 * Lo que decide si un mensaje ya publicado se queda como está. Va aparte del
 * texto a propósito: el texto lleva la EPSS con un decimal y la firma la lleva
 * por bandas, así que el mensaje enseña el número exacto del día en que se editó
 * pero un vaivén del 0,08 al 0,09 % no dispara una edición.
 */
function firmaFila(fila, sala, vc = null) {
  // La ficha de VulnCheck va en la firma porque es de donde sale el texto del
  // mensaje: sin ella, cambiar el nombre o el plazo en el catálogo no reeditaría
  // nada. La puntuación no entra —se pide aparte, y solo de lo que se manda—,
  // pero el score de la EUVD sí sigue estando, así que un reanálisis mueve la
  // firma igual y el mensaje se pone al día con él.
  const deVulncheck = vc
    ? [
        vc.fecha ?? "",
        vc.cisaFecha ?? "",
        vc.plazo ?? "",
        vc.nombre ?? "",
        vc.descripcion ?? "",
        vc.accion ?? "",
        vc.vendor ?? "",
        vc.producto ?? "",
        (vc.cwes ?? []).join(","),
        vc.ransomware ? "R" : "",
        vc.canarios ? "C" : "",
      ].join("\u0002")
    : "";

  return firmaCorta(
    [
      sala,
      fila.score ?? "",
      bandaEpss(fila.epss),
      fila.kev ? `${fila.kev.fecha ?? ""}|${(fila.kev.fuentes ?? []).join(",")}` : "",
      (fila.cwes ?? []).map((c) => c?.id).join(","),
      fila.nombre ?? "",
      fila.descripcion ?? "",
      fila.vendor ?? "",
      fila.producto ?? "",
      fila.fecha ?? "",
      deVulncheck,
    ].join("\u0001")
  );
}

/**
 * El chat de una sala, con TELEGRAM_CHAT_ID de respaldo para las que no tengan
 * el suyo. El respaldo solo recoge lo que pase el umbral: si no, quien tenga
 * montado un único chat pasaría de 183 mensajes al día a los 352 de la ventana
 * entera sin haber tocado nada. La excepción es KEV, que va siempre — que algo
 * se esté explotando importa aunque puntúe un 5.
 */
function destinoDe(sala, fila) {
  if (TG_SALAS[sala]) return TG_SALAS[sala];
  if (sala === "kev") return TG_CHAT;
  return typeof fila.score === "number" && fila.score >= TG_UMBRAL ? TG_CHAT : "";
}

/**
 * Una sala puede apuntar a un tema de un grupo con foro: "-1001234567890:7" es
 * el tema 7 de ese grupo. Los identificadores de chat no llevan dos puntos, así
 * que partir por ahí no tiene ambigüedad.
 */
function partirDestino(destino) {
  const corte = String(destino).indexOf(":");
  if (corte === -1) return { chat: destino, hilo: null };

  const hilo = Number(destino.slice(corte + 1));
  return { chat: destino.slice(0, corte), hilo: Number.isInteger(hilo) ? hilo : null };
}

/** HTML es el parse_mode con menos que escapar: tres caracteres y se acabó. */
const escaparHtml = (texto) =>
  String(texto ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

/**
 * Los mensajes van en inglés porque es el idioma de las fuentes: el título viene
 * de cve.org, las CWE de MITRE y los catálogos KEV de CISA y ENISA. Traducir la
 * mitad de cada mensaje dejaba frases a medio idioma.
 */
const TG_ETIQUETA_SALA = {
  kev: "KEV",
  critica: "Critical",
  alta: "High",
  media: "Medium",
  baja: "Low",
  sin_puntuar: "Unscored",
};

const TG_MARCA = {
  critica: "\u{1F534} CRITICAL",
  alta: "\u{1F7E0} HIGH",
  media: "\u{1F7E1} MEDIUM",
  baja: "\u{1F535} LOW",
  sin_puntuar: "\u{26AA} UNSCORED",
};

// La descripción va en una cita: por encima de TG_DESC_PLEGABLE, Telegram la
// pliega y deja el resto del mensaje a la vista. El tope duro existe porque hay
// descripciones de 4.000 caracteres y un mensaje entero no puede pasar de 4.096.
const TG_DESC_PLEGABLE = 300;
const TG_DESC_MAX = 3000;

const TG_CWE_VISIBLES = 3; // el mismo tope que la tabla; el resto va como "+n"

// A cuánto llega cada subíndice, que es lo que los hace legibles: un 1.8 de
// explotabilidad no dice nada, un "1.8 / 3.9" dice que cuesta explotarla. Los
// topes no son los mismos en cada versión del CVSS —la 2.0 puntúa los dos sobre
// 10— y la 4.0 no publica subíndices, así que ahí no sale la línea.
const TG_CVSS_TOPES = {
  "2.0": { explotabilidad: 10, impacto: 10 },
  "3.0": { explotabilidad: 3.9, impacto: 6 },
  "3.1": { explotabilidad: 3.9, impacto: 6 },
};

// La acción recomendada es plantilla —19 textos distintos para 1.000 entradas—
// pero las hay de 520 caracteres. El tope está para que una futura más larga no
// se coma el margen hasta los 4.096 de un mensaje.
const TG_ACCION_MAX = 600;

// Las referencias con las que VulnCheck sostiene que se está explotando: unas
// son el informe de quien lo vio, otras el aviso del fabricante. Son las únicas
// que lleva el mensaje. El catálogo trae 32 de media por CVE, así que se cortan
// en dos —con eso ya se puede verificar— y el resto se resume en un "+n".
const TG_EVIDENCIAS_VISIBLES = 2;

/**
 * Un mensaje por vulnerabilidad, en cuatro bloques: cabecera con lo que se ve en
 * la notificación del móvil (criticidad, puntuación e identificador), título,
 * la alerta de explotación, los datos etiquetados y los enlaces.
 *
 * **Todo lo que dice sale de VulnCheck**: `vc` es su ficha del catálogo de KEV
 * —nombre, descripción, fabricante, producto, CWE, fechas, ransomware, plazo y
 * pruebas de explotación— y `nvd` es la puntuación y la fecha de publicación,
 * del NVD que sirve el propio VulnCheck. La fila solo pone el identificador.
 *
 * Eso deja fuera la EPSS, que la sirve FIRST y VulnCheck no: en un mensaje que
 * solo sale de lo ya explotado tampoco pintaba mucho una probabilidad de que
 * llegue a explotarse. La tabla la sigue enseñando.
 *
 * El identificador va en <code> para que Telegram lo ponga en monoespaciada y
 * se pueda copiar tocándolo, que es lo primero que se hace con un CVE.
 *
 * `previa` solo llega cuando el mensaje se muda de sala, y entonces abre
 * diciéndolo: en la sala de KEV, la mitad de los mensajes son CVE de las que ya
 * se avisó hace días, y sin ese aviso parecen recién publicadas.
 *
 * `actualizado` solo llega en las ediciones, y deja constancia de la hora. Sin
 * eso un mensaje cambiaría de contenido sin que se note: Telegram no marca de
 * ninguna manera los mensajes que edita un bot.
 */
function mensajeTelegram(fila, vc = null, nvd = null, previa = null, actualizado = null) {
  const lineas = [];

  if (previa) {
    const antes = TG_ETIQUETA_SALA[previa.sala] ?? previa.sala;
    const cuando = typeof previa.fecha === "string" ? ` on ${previa.fecha.slice(0, 10)}` : "";
    // El mensaje de la sala anterior se borra al mudarse, así que este encabezado
    // no compite con nada: es lo único que queda de que ya se había avisado.
    const sube = prioridadSala(salaDe(fila)) > prioridadSala(previa.sala);
    const marca = sube
      ? "\u{2B06}\u{FE0F} <b>Escalated</b>"
      : "\u{2B07}\u{FE0F} <b>Downgraded</b>";
    lineas.push(`${marca} — previously reported as ${antes}${cuando}`, "");
  }

  // El score del NVD que sirve VulnCheck; la severidad, del mismo corte que usa
  // la tabla, para que la marca de la cabecera diga lo mismo que el número.
  const score = typeof nvd?.score === "number" ? nvd.score : null;
  const marca = TG_MARCA[severidad(score)] ?? TG_MARCA.sin_puntuar;
  // Sin puntuación la cabecera se queda con la marca a secas: un CVSS 0.0 que
  // nadie ha puesto sería peor que no decir nada.
  const puntuacion = score > 0 ? ` · CVSS <b>${score.toFixed(1)}</b>` : "";
  lineas.push(`${marca}${puntuacion} · <code>${escaparHtml(fila.cve ?? fila.euvd)}</code>`);

  // La descripción trae saltos de línea a media frase, así que se normaliza.
  const descripcion = String(vc?.descripcion ?? "").replace(/\s+/g, " ").trim();

  // El catálogo trae las dos cosas, pero a veces el nombre es el primer trozo de
  // la descripción: repetirlo sería enseñar dos veces la misma frase.
  const titulo = String(vc?.nombre ?? "").trim();
  if (titulo && !descripcion.startsWith(titulo.replace(/…$/, "").trim())) {
    lineas.push(`<b>${escaparHtml(titulo)}</b>`);
  }

  // La alerta sale entera de la ficha de VulnCheck: su fecha, y la de CISA si
  // además la confirmó, que el propio catálogo trae en `cisa_date_added`.
  const fuentes = ["VulnCheck KEV", ...(vc?.cisaFecha ? ["CISA KEV"] : [])].join(" · ");
  const desde = vc?.fecha ? `, added ${vc.fecha}` : "";
  lineas.push("", `\u{26A0}\u{FE0F} <b>Actively exploited</b> — ${escaparHtml(fuentes)}${desde}`);

  // Las dos cosas que separan lo urgente de lo muy urgente, y que no las da
  // ningún otro catálogo: si hay ransomware usándola y si la han visto entrar
  // en los señuelos de VulnCheck.
  if (vc?.ransomware) lineas.push("\u{1F513} <b>Known ransomware campaign use</b>");
  if (vc?.canarios) lineas.push("\u{1F4E1} Exploitation seen by VulnCheck canaries");

  if (descripcion) {
    const recortada =
      descripcion.length > TG_DESC_MAX
        ? descripcion.slice(0, TG_DESC_MAX).replace(/\s+\S*$/, "") + "…"
        : descripcion;
    const cita = recortada.length > TG_DESC_PLEGABLE ? "blockquote expandable" : "blockquote";
    lineas.push("", `<${cita}>${escaparHtml(recortada)}</blockquote>`);
  }

  // Datos etiquetados: se leen en diagonal y cada uno se calla si no hay dato,
  // que es mejor que una fila con un guion.
  const datos = [];

  if (vc?.vendor) datos.push(`<b>Vendor:</b> ${escaparHtml(vc.vendor)}`);
  if (vc?.producto && vc.producto !== vc.vendor) {
    datos.push(`<b>Product:</b> ${escaparHtml(vc.producto)}`);
  }

  // Enlazadas a cwe.mitre.org, igual que en la tabla, y con el mismo tope de tres
  // visibles y un "+n" con el resto: en un mensaje de móvil, seis identificadores
  // seguidos ocupan más que todo lo demás junto.
  //
  // Manda las del catálogo de KEV, que van a la causa de lo que se está
  // explotando; las del NVD entran solo si el catálogo no trae ninguna.
  const cwes = (vc?.cwes?.length ? vc.cwes : (nvd?.cwes ?? [])).filter((id) => /^CWE-\d+$/.test(id));
  if (cwes.length) {
    const enlazadas = cwes
      .slice(0, TG_CWE_VISIBLES)
      .map((id) => `<a href="https://cwe.mitre.org/data/definitions/${id.slice(4)}.html">${id}</a>`)
      .join(", ");
    const resto = cwes.length - TG_CWE_VISIBLES;
    datos.push(`<b>CWE:</b> ${enlazadas}${resto > 0 ? ` +${resto}` : ""}`);
  }

  // Los dos subíndices en una línea, cada uno contra su tope. Separan dos cosas
  // que el score junta: lo fácil que es llegar y lo que se lleva por delante.
  const topes = TG_CVSS_TOPES[nvd?.cvss ?? ""];
  if (topes && (nvd.explotabilidad != null || nvd.impacto != null)) {
    const partes = [];
    if (nvd.explotabilidad != null) {
      partes.push(`<b>Exploitability:</b> ${nvd.explotabilidad.toFixed(1)} / ${topes.explotabilidad.toFixed(1)}`);
    }
    if (nvd.impacto != null) {
      partes.push(`<b>Impact:</b> ${nvd.impacto.toFixed(1)} / ${topes.impacto.toFixed(1)}`);
    }
    datos.push(partes.join(" · "));
  }

  // Con hora y diciendo que es UTC: el NVD la publica sin marca horaria, y una
  // fecha a secas hace pensar que la vulnerabilidad lleva un día entero fuera
  // cuando puede llevar veinte minutos.
  if (nvd?.publicado) {
    const dia = nvd.publicado.slice(0, 10);
    const hora = nvd.publicado.slice(11, 16);
    datos.push(`<b>Published:</b> ${dia}${/^\d{2}:\d{2}$/.test(hora) ? ` ${hora} UTC` : ""}`);
  }
  // El plazo de CISA, que el catálogo de VulnCheck arrastra. En una lista de cosas
  // que ya se están explotando es el único dato con una fecha límite de verdad.
  if (vc?.plazo) datos.push(`<b>Patch by:</b> ${vc.plazo}`);

  if (datos.length) lineas.push("", ...datos);

  // Lo que el catálogo dice que hay que hacer. Va después de los datos y antes de
  // los enlaces porque es la conclusión del mensaje: lo de arriba explica por qué
  // corre prisa y esto dice qué se hace con ello.
  const accion = String(vc?.accion ?? "").replace(/\s+/g, " ").trim();
  if (accion) {
    const recortada =
      accion.length > TG_ACCION_MAX
        ? accion.slice(0, TG_ACCION_MAX).replace(/\s+\S*$/, "") + "…"
        : accion;
    lineas.push("", `\u{1F6E0}\u{FE0F} <b>Required action:</b> ${escaparHtml(recortada)}`);
  }

  // La línea de abajo son las referencias de VulnCheck y nada más. Ni la ficha de
  // la EUVD —iba primera por ser de donde salía el CVSS, y el CVSS ya no sale de
  // ahí— ni el registro del CVE: el identificador está arriba en monoespaciada,
  // que es lo que se copia, y lo que se abre desde el mensaje es lo que justifica
  // el aviso. El "+n" dice cuántas más hay, igual que en las CWE.
  const evidencias = vc?.evidencias ?? [];
  if (evidencias.length) {
    const enlaces = evidencias
      .slice(0, TG_EVIDENCIAS_VISIBLES)
      .map((url, i) => `<a href="${escaparHtml(url)}">Evidence${i > 0 ? ` ${i + 1}` : ""}</a>`);
    const resto = evidencias.length - TG_EVIDENCIAS_VISIBLES;
    lineas.push("", enlaces.join(" · ") + (resto > 0 ? ` +${resto}` : ""));
  }

  if (actualizado) lineas.push("", `<i>Updated ${actualizado.slice(0, 16).replace("T", " ")} UTC</i>`);

  return lineas.join("\n");
}

/**
 * Una sola puerta a la API. Envíos, ediciones y borrados cuentan todos contra el
 * mismo límite del grupo, así que conviene tratarlos igual y devolver siempre la
 * espera que pida un 429 y el motivo, que es lo que distingue un fallo de verdad
 * de un "ese mensaje ya no existe".
 *
 * @returns {Promise<{ok:boolean, esperar:number, resultado:any, motivo:string}>}
 */
async function telegramLlamar(metodo, cuerpo) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/${metodo}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cuerpo),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    const json = await r.json().catch(() => null);
    if (r.ok && json?.ok === true) return { ok: true, esperar: 0, resultado: json.result, motivo: "" };

    const motivo = String(json?.description ?? `HTTP ${r.status}`);
    log(`Telegram: ${metodo} falló — ${motivo}`);
    return { ok: false, esperar: Number(json?.parameters?.retry_after ?? 0), resultado: null, motivo };
  } catch (e) {
    log(`Telegram: ${metodo} falló (${e.message})`);
    return { ok: false, esperar: 0, resultado: null, motivo: e.message };
  }
}

/**
 * Devuelve dónde quedó el mensaje —chat e identificador— porque sin eso no se
 * puede ni editar ni borrar después, y cuánto esperar si Telegram corta (429).
 */
async function telegramEnviar(destino, texto) {
  const { chat, hilo } = partirDestino(destino);

  const r = await telegramLlamar("sendMessage", {
    chat_id: chat,
    ...(hilo != null ? { message_thread_id: hilo } : {}),
    text: texto,
    parse_mode: "HTML",
    disable_web_page_preview: true,
  });

  return { enviado: r.ok, esperar: r.esperar, chat, mensaje: r.resultado?.message_id ?? null };
}

/**
 * Pone al día un mensaje sin sacarlo de su tema y sin notificar a nadie: es lo
 * que se quiere cuando una CVE cambia pero se queda en la misma sala.
 *
 * "message is not modified" cuenta como hecha —el texto ya es el que toca, y
 * reintentarlo cada pasada sería pelearse con Telegram para siempre—, y "not
 * found" también, porque es un mensaje borrado a mano: quien llama se entera por
 * `perdido` y tira el identificador en vez de reintentar eternamente.
 */
async function telegramEditar(chat, mensaje, texto) {
  const r = await telegramLlamar("editMessageText", {
    chat_id: chat,
    message_id: mensaje,
    text: texto,
    parse_mode: "HTML",
    disable_web_page_preview: true,
  });

  if (r.ok || /not modified/i.test(r.motivo)) return { hecha: true, esperar: 0, perdido: false };

  const perdido = /not found/i.test(r.motivo);
  return { hecha: perdido, esperar: r.esperar, perdido };
}

/**
 * Borra el mensaje de la sala que ha dejado de corresponder. El bot es
 * administrador del grupo con permiso de borrado, así que no le aplica el tope de
 * 48 horas de los mensajes normales: dentro de la ventana de 14 días se puede
 * borrar cualquiera. Si algún día se le quita el permiso, esto empieza a fallar y
 * los mensajes viejos se quedan donde están; se ve en el log.
 */
async function telegramBorrar(chat, mensaje) {
  const r = await telegramLlamar("deleteMessage", { chat_id: chat, message_id: mensaje });
  if (r.ok || /not found/i.test(r.motivo)) return { hecho: true, esperar: 0 };
  return { hecho: false, esperar: r.esperar };
}

/**
 * Avisa por Telegram y mantiene al día lo ya avisado.
 *
 * Lo que decide qué hacer con cada fila no es la fecha sino .notificado.json,
 * donde queda a qué sala fue cada una, con qué identificador de mensaje y con qué
 * firma. La ventana se solapa entre pasadas y los datos llegan tarde —una CVE
 * entra sin CVSS y recibe un 9.8 tres pasadas después—, así que filtrar por fecha
 * dejaría fuera justo lo que más importa.
 *
 * Con eso, tres caminos:
 *
 *   - Sin mensaje previo: se envía, si todavía es una noticia. Lo de la ventana
 *     siempre lo es; lo que entra por el catálogo de KEV, solo si acaba de entrar
 *     en él. Ver esNoticia().
 *   - Misma sala y firma distinta: se edita en el sitio. Telegram no notifica las
 *     ediciones de un bot, así que el mensaje se pone al día sin sonar y sin
 *     moverse del tema, que es lo que se quiere para un 3.1 que pasa a 3.4.
 *   - Otra sala: el tema es la clasificación, así que el mensaje se muda. Se
 *     publica en la sala nueva y se borra el de la vieja, en ese orden: si algo
 *     falla, preferimos un mensaje mal colocado a ninguno.
 *
 * Las mudanzas van en los dos sentidos. Que la EUVD rebaje un 9.8 a un 5.0 no es
 * una noticia, pero dejar ese mensaje en la sala de críticas sí es un problema:
 * la sala dejaría de querer decir lo que dice.
 *
 * Lo que sale de la ventana deja de mantenerse y su último mensaje se queda
 * publicado tal cual: la alternativa era guardar el estado para siempre. Pero el
 * apunte sobrevive TG_OLVIDO_DIAS a la última vez que se vio la fila, no a la
 * pasada en que faltó: sin ese margen, media ventana que no se descargue un día
 * es media ventana reavisada al siguiente.
 *
 * Las filas sin sala configurada se anotan igual, sin enviar. Así, el día que
 * montes la sala de medias, no te caen encima las 1.700 de la ventana: solo llega
 * lo que aparezca a partir de entonces.
 *
 * La primera ejecución no manda nada: siembra el fichero con lo que ya hay.
 *
 * Va después de escribir el JSON a propósito: que Telegram no conteste no puede
 * dejar la web sin actualizar.
 */
async function notificarTelegram(filas, registroSembrado = null, vulncheck = null) {
  const salasConfiguradas = Object.values(TG_SALAS).filter(Boolean).length;

  if (!TG_TOKEN || (!TG_CHAT && salasConfiguradas === 0)) {
    log("Telegram: sin TELEGRAM_BOT_TOKEN o sin ningún chat configurado, no aviso.");
    return;
  }

  // Sin el catálogo de VulnCheck no se puede decidir qué avisar, así que no se
  // avisa: la pasada se va sin tocar Telegram y sin escribir el estado. Escribirlo
  // sería peor que no hacer nada — lo de hoy quedaría anotado como visto y su
  // aviso se perdería para siempre. En diez minutos hay otra pasada.
  if (!vulncheck) {
    log("Telegram: sin catálogo de VulnCheck no sé qué avisar; esta pasada no toco nada.");
    return;
  }

  const estado = await leerCache(estadoTelegram);
  const previas = estado.avisadas && typeof estado.avisadas === "object" ? estado.avisadas : {};

  // El formato viejo guardaba `euvd: fecha` en vez de `euvd: {sala, fecha}`. Se
  // reconstruye entero y sin avisar, como una siembra: reaprovecharlo mandaría un
  // reaviso por cada fila que antes no tenía sala anotada.
  //
  // Las entradas sin `mensaje` —las escritas antes de que se guardara el
  // identificador— no son ni editables ni movibles, pero eso no rompe nada: se
  // les anota la firma, siguen contando para no reavisar, y en 14 días salen de la
  // ventana solas.
  const formatoViejo = Object.values(previas).some((v) => typeof v !== "object" || v === null);
  const primeraVez = typeof estado.sembrado !== "string";

  // Sembrar el catálogo de KEV mete de golpe ~1.300 filas viejas que nunca se
  // avisaron. Sin este marcador, la primera pasada tras el cambio intentaría
  // volcarlas todas en la sala de KEV: a 3,5 s cada una son más de una hora de
  // mensajes sobre cosas explotadas desde hace años, que no es una noticia.
  // Se anotan calladas una vez y a partir de ahí solo llega lo que entre nuevo
  // en el catálogo, que es el mismo trato que reciben las salas recién montadas.
  // Con la memoria del feed sembrada, este marcador sobra y además estorba: a
  // Telegram ya solo le llega lo que .vistas.json da por nuevo, así que un volcado
  // del catálogo es imposible, y silenciar el primer KEV nuevo sería perder justo
  // el aviso que más importa. La red sigue existiendo para un montaje sin registro.
  const kevSinSembrar = typeof estado.sembradoKev !== "string" && !registroSembrado;

  // El marcador solo se pone si el catálogo llegó de verdad. Si la petición falló,
  // `filas` no trae nada de fuera de ventana y darla por sembrada dejaría el
  // volcado para la pasada siguiente, que es justo lo que se quiere evitar.
  const hayFueraDeVentana = filas.some((f) => f.fueraDeVentana);
  const marcaKev = (ahora) => estado.sembradoKev ?? (hayFueraDeVentana ? ahora : undefined);

  const ahora = new Date().toISOString();

  // La poda: lo que sigue apareciendo se marca visto, y lo que lleva
  // TG_OLVIDO_DIAS sin aparecer se olvida, para que el fichero no crezca sin fin.
  //
  // Lo que no vale es quedarse solo con lo que trae esta pasada. `filas` no es la
  // ventana, es lo que se ha podido descargar de la ventana: una página que falla
  // o un catálogo de KEV que no baja se lleva por delante cientos de apuntes, y
  // sin apunte esas filas vuelven a contar como no avisadas en la pasada
  // siguiente. Así es como acaban en la sala de KEV CVE de hace años.
  const presentes = new Set(filas.map((f) => f.euvd));
  const olvidar = Date.parse(ahora) - TG_OLVIDO_DIAS * 86400000;
  const vigentes = {};
  for (const [euvd, previa] of Object.entries(previas)) {
    if (presentes.has(euvd)) {
      vigentes[euvd] = previa && typeof previa === "object" ? { ...previa, visto: ahora } : previa;
      continue;
    }

    // Sin fecha que mirar —las entradas del formato viejo son una cadena— se deja
    // caer: ese formato lo reconstruye entero el bloque de siembra de más abajo.
    const visto = Date.parse(previa?.visto ?? previa?.fecha ?? "");
    if (!Number.isNaN(visto) && visto >= olvidar) vigentes[euvd] = previa;
  }

  // La pausa va antes que nada: ni siembra, ni avisos, ni ediciones. Lo que hay
  // se anota como visto y ahí se queda. Si una fila ya tenía mensaje publicado se
  // conserva su apunte tal cual —identificador y sala incluidos— para que al
  // reanudar se pueda seguir editando y moviendo en vez de duplicarla.
  if (TG_EN_PAUSA) {
    for (const fila of filas) {
      const sala = salaDe(fila);
      const previa = vigentes[fila.euvd] ?? null;
      const firma = firmaFila(fila, sala, fichaDe(fila, vulncheck));
      vigentes[fila.euvd] =
        previa && typeof previa === "object"
          ? { ...previa, visto: ahora, firma }
          : { sala, fecha: ahora, visto: ahora, enviada: false, firma };
    }

    await escribirJson(estadoTelegram, {
      sembrado: estado.sembrado ?? ahora,
      sembradoKev: marcaKev(ahora),
      avisadas: vigentes,
    });
    log(
      `Telegram: en pausa (TELEGRAM_PAUSA). Anotadas ${filas.length} vulnerabilidades sin avisar; ` +
        "quita la pausa para que vuelvan a salir avisos de lo que aparezca a partir de entonces."
    );
    return;
  }

  if (primeraVez || formatoViejo) {
    for (const fila of filas) {
      const sala = salaDe(fila);
      vigentes[fila.euvd] = {
        sala,
        fecha: ahora,
        visto: ahora,
        enviada: false,
        firma: firmaFila(fila, sala, fichaDe(fila, vulncheck)),
      };
    }

    await escribirJson(estadoTelegram, {
      sembrado: estado.sembrado ?? ahora,
      sembradoKev: marcaKev(ahora),
      avisadas: vigentes,
    });
    log(
      `Telegram: ${primeraVez ? "primera ejecución" : "estado en formato antiguo"}, siembro ` +
        `${filas.length} vulnerabilidades sin avisar. A partir de la siguiente pasada solo llega lo nuevo.`
    );
    return;
  }

  const envios = []; // primer aviso y mudanzas: los dos acaban en un sendMessage
  const ediciones = []; // misma sala, contenido distinto

  for (const fila of filas) {
    const sala = salaDe(fila);
    const previa = vigentes[fila.euvd] ?? null;
    const vc = fichaDe(fila, vulncheck);
    const firma = firmaFila(fila, sala, vc);
    const destino = destinoDe(sala, fila);

    // El filtro: lo que VulnCheck no da por explotado se anota y ahí se queda.
    // No se envía, no se edita y no se mueve de sala.
    //
    // Tampoco se borra lo que se publicó antes de poner el filtro: esos mensajes
    // se quedan donde están y su apunte se cae solo en TG_OLVIDO_DIAS. Borrarlos
    // sería un barrido de cientos de mensajes que nadie ha pedido, y el grupo
    // queda limpio igual en dos semanas sin tocar nada.
    if (!esVulncheckKev(fila)) {
      vigentes[fila.euvd] =
        previa && typeof previa === "object"
          ? { ...previa, visto: ahora, firma }
          : { sala, fecha: ahora, visto: ahora, enviada: false, firma };
      continue;
    }

    // La siembra del catálogo: solo la primera vez y solo lo que entra por él.
    // Lo que ya estaba anotado sigue su camino normal, incluidas las ediciones.
    if (kevSinSembrar && fila.fueraDeVentana && !previa) {
      vigentes[fila.euvd] = { sala, fecha: ahora, visto: ahora, enviada: false, firma };
      continue;
    }

    // Primer aviso de algo que ya no es noticia: se anota callado, como la
    // siembra. Es la red que hace que el estado no sea lo único que separa la sala
    // de KEV de un volcado del catálogo: aunque el fichero se pierda entero, de
    // fuera de la ventana solo se avisa lo que acaba de entrar en KEV.
    if (!previa && !esNoticia(fila, ahora)) {
      vigentes[fila.euvd] = { sala, fecha: ahora, visto: ahora, enviada: false, firma };
      continue;
    }

    // Ya anotada y sigue en su sala: como mucho, una edición silenciosa.
    if (previa && previa.sala === sala) {
      if (previa.firma === firma) continue;
      if (previa.enviada && previa.mensaje) ediciones.push({ fila, sala, previa, firma, vc });
      else vigentes[fila.euvd] = { ...previa, firma };
      continue;
    }

    // Sin sala montada: se anota y no se vuelve a mirar mientras no cambie de
    // sala. Si venía publicada de otra, se borra: allí ya no pinta nada.
    if (!destino) {
      if (previa?.mensaje) envios.push({ fila, sala, destino: "", previa, firma, vc, soloBorrar: true });
      else vigentes[fila.euvd] = { sala, fecha: ahora, visto: ahora, enviada: false, firma };
      continue;
    }

    envios.push({ fila, sala, destino, previa, firma, vc, soloBorrar: false });
  }

  if (envios.length === 0 && ediciones.length === 0) {
    log("Telegram: nada nuevo que avisar ni que actualizar.");
    await escribirJson(estadoTelegram, {
      sembrado: estado.sembrado,
      sembradoKev: marcaKev(ahora),
      avisadas: vigentes,
    });
    return;
  }

  // Por sala y luego por puntuación: si un día hay atasco, lo que ya se está
  // explotando sale delante.
  envios.sort(
    (a, b) => prioridadSala(b.sala) - prioridadSala(a.sala) || (b.fila.score ?? 0) - (a.fila.score ?? 0)
  );

  // Envíos, ediciones y borrados van todos contra el mismo límite del grupo, así
  // que la pausa la lleva un único contador y no cada bucle por su cuenta.
  let llamadas = 0;
  const ritmo = async () => {
    if (llamadas > 0) await dormir(TG_PAUSA_MS);
    llamadas++;
  };

  const enviadas = {};
  let total = 0;
  let hechos = 0;
  let mudadas = 0;
  let editadas = 0;
  let cortado = false;

  for (const { fila, sala, destino, previa, firma, vc, soloBorrar } of envios) {
    // El tope es por sala: el límite de Telegram es por chat, así que un atasco en
    // medias no tiene por qué retrasar el aviso de una crítica.
    const cupo = (enviadas[sala] ?? 0) + 1;
    if (!soloBorrar && cupo > TG_MAX_MENSAJES) continue; // sin marcar: sale en la siguiente pasada

    let apunte = { sala, fecha: ahora, visto: ahora, enviada: false, firma };

    if (!soloBorrar) {
      // El encabezado de mudanza solo tiene sentido si de la anterior se llegó a
      // avisar; si no, para quien lo lee es un mensaje nuevo y punto.
      await ritmo();
      // La puntuación se pide aquí y no antes: solo hace falta para lo que de
      // verdad se manda, que con el filtro puesto son unos pocos por pasada.
      const texto = mensajeTelegram(fila, vc, await datosVulncheckNvd(fila.cve), previa?.enviada ? previa : null);
      const { enviado, esperar, chat, mensaje } = await telegramEnviar(destino, texto);

      if (!enviado) {
        // 429: Telegram dice cuánto callar. Cortamos y lo retomamos en la pasada
        // siguiente; lo no enviado se queda sin marcar, así que no se pierde.
        if (esperar > 0) {
          log(`Telegram: me pide esperar ${esperar} s; lo dejo para la siguiente pasada.`);
          cortado = true;
          break;
        }
        continue; // sin marcar: se reintenta en la siguiente pasada
      }

      apunte = { sala, fecha: ahora, visto: ahora, enviada: true, chat, mensaje, firma };
      enviadas[sala] = cupo;
      total++;
    }

    // Y ahora el viejo, que ya no corresponde a esta sala. Va después del envío a
    // propósito: si falla el borrado queda un duplicado, pero si fallara al revés
    // nos quedaríamos sin aviso.
    if (previa?.mensaje && previa?.chat) {
      await ritmo();
      const { hecho } = await telegramBorrar(previa.chat, previa.mensaje);
      if (hecho) mudadas++;
      else log(`Telegram: no pude borrar el mensaje de ${fila.euvd} en la sala ${previa.sala}.`);
    }

    vigentes[fila.euvd] = apunte;
    hechos++;
  }

  // Las ediciones, al final: no notifican a nadie, así que si la pasada se queda
  // sin tiempo o sin cupo, lo justo es que cedan el turno a los avisos.
  if (!cortado) {
    for (const { fila, sala, previa, firma, vc } of ediciones) {
      if (editadas >= TG_MAX_EDICIONES) break; // el resto, en la siguiente pasada

      await ritmo();
      const nvd = await datosVulncheckNvd(fila.cve);
      const { hecha, esperar, perdido } = await telegramEditar(
        previa.chat,
        previa.mensaje,
        mensajeTelegram(fila, vc, nvd, null, ahora)
      );

      if (!hecha) {
        if (esperar > 0) {
          log(`Telegram: me pide esperar ${esperar} s; dejo las ediciones para la siguiente pasada.`);
          cortado = true;
          break;
        }
        continue;
      }

      // Si el mensaje ya no existe se olvida el identificador y la fila vuelve a
      // contar como anotada pero no publicada: no se reenvía —eso sería avisar dos
      // veces de lo mismo— pero tampoco se reintenta editar cada pasada.
      vigentes[fila.euvd] = perdido
        ? { sala, fecha: previa.fecha, visto: ahora, enviada: false, firma }
        : { ...previa, firma };
      editadas++;
    }
  }

  await escribirJson(estadoTelegram, {
    sembrado: estado.sembrado,
    sembradoKev: marcaKev(ahora),
    avisadas: vigentes,
  });

  const desglose = Object.entries(enviadas)
    .map(([sala, n]) => `${sala} ${n}`)
    .join(", ");
  const cola = envios.length - hechos + (ediciones.length - editadas);
  log(
    `Telegram: ${total} avisos enviados${desglose ? ` (${desglose})` : ""}` +
      (mudadas ? `, ${mudadas} movidos de sala` : "") +
      (editadas ? `, ${editadas} actualizados en el sitio` : "") +
      (cola > 0 ? `, ${cola} para la siguiente pasada${cortado ? " (me cortaron)" : ""}` : "")
  );
}

// ---------------------------------------------------------------- cerrojo

/**
 * Un solo sync a la vez. Con el cron cada 15 minutos y pasadas completas de tres
 * minutos, dos procesos solapados se pisarían las cachés y el rename atómico.
 *
 * Node no trae flock, así que el cerrojo es un fichero con la hora de arranque.
 * Si es más viejo que LOCK_CADUCIDAD_MS damos por muerto al anterior y seguimos:
 * una ejecución matada a medias dejaría el fichero ahí para siempre y el cron no
 * volvería a correr nunca.
 */
async function tomarCerrojo() {
  for (let intento = 0; intento < 2; intento++) {
    try {
      const fd = await open(cerrojoRuta, "wx");
      await fd.writeFile(JSON.stringify({ pid: process.pid, inicio: Date.now() }));
      await fd.close();

      process.on("exit", () => {
        try {
          unlinkSync(cerrojoRuta);
        } catch {
          // Si ya no está, mejor.
        }
      });
      return true;
    } catch (e) {
      if (e.code !== "EEXIST") throw e;

      let inicio = 0;
      try {
        inicio = JSON.parse(await readFile(cerrojoRuta, "utf8"))?.inicio ?? 0;
      } catch {
        // Cerrojo ilegible: lo tratamos como caducado.
      }

      if (Date.now() - inicio < LOCK_CADUCIDAD_MS) return false;

      log("El cerrojo anterior está caducado; lo retiro y sigo.");
      try {
        await unlink(cerrojoRuta);
      } catch {
        // Otro proceso se nos adelantó; el siguiente intento lo dirá.
      }
    }
  }
  return false;
}

/**
 * La memoria del feed. Decide qué se publica comparando lo que trae la pasada con
 * lo que ya se había visto antes, y devuelve solo lo nuevo, con su caducidad.
 *
 * Por qué por identificador y no por fecha: la EUVD ordena por fecha de
 * actualización, no de publicación, y las fichas asoman tarde —se ven entradas
 * publicadas hora y media antes de aparecer en el listado—. Un corte por reloj
 * dejaría fuera para siempre todo lo que se publique antes del corte y aparezca
 * después, que en un feed de vulnerabilidades es justo lo que no se puede perder.
 * Con el registro da igual cuándo diga la EUVD que se publicó: si no se había
 * visto, es nueva.
 *
 * La primera pasada no publica nada: anota las que hay y ya. Es lo que permite
 * empezar de cero sin volcar de golpe los 14 días de historia que la API sigue
 * devolviendo —y sin que Telegram los tome por novedades—. Para volver a empezar,
 * se borra .vistas.json y la pasada siguiente vuelve a ser la primera.
 */
async function filtrarNuevas(filas, ahora) {
  const estado = await leerCache(registroVistas);
  const conocidas = estado.ids && typeof estado.ids === "object" ? estado.ids : {};
  const primeraRevision = typeof estado.sembrado !== "string";

  const ahoraIso = ahora.toISOString();
  const ahoraMs = ahora.getTime();
  // Lo anotado en la primera revisión lleva su misma marca de tiempo, y no se
  // publica nunca: es justo el fondo del que se quería vaciar el feed. Solo sube
  // a la web lo que se haya visto por primera vez después de ese momento.
  const sembradoMs = Date.parse(estado.sembrado ?? ahoraIso);
  const caduca = VENTANA_DIAS * 86400000;
  const olvido = VISTAS_OLVIDO_DIAS * 86400000;

  const vigentes = {};
  const publicables = [];
  let caducadas = 0;
  let nuevas = 0;

  for (const fila of filas) {
    const previa = conocidas[fila.euvd];
    const primera = typeof previa?.p === "string" ? previa.p : null;

    if (primera === null) {
      vigentes[fila.euvd] = { p: ahoraIso, v: ahoraIso };
      if (!primeraRevision) {
        publicables.push(fila);
        nuevas++;
      }
      continue;
    }

    // Se conserva la fecha del primer avistamiento: es la que manda la caducidad,
    // no la de publicación. Una ficha que la EUVD publica con fecha de hace tres
    // días entra hoy y se queda sus 14 días completos, que es lo útil.
    vigentes[fila.euvd] = { p: primera, v: ahoraIso };
    const desde = Date.parse(primera);
    if (desde <= sembradoMs) continue; // del fondo inicial: ni se publica ni caduca
    if (ahoraMs - desde <= caduca) publicables.push(fila);
    else caducadas++;
  }

  // Lo que no ha venido en esta pasada sigue en el registro mientras no lleve
  // demasiado sin verse. Si se olvidara antes de que la EUVD deje de devolverlo,
  // la pasada siguiente lo tomaría por nuevo: así es como una descarga corta se
  // convierte en una avalancha de avisos de cosas de hace dos semanas.
  for (const [euvd, entrada] of Object.entries(conocidas)) {
    if (vigentes[euvd]) continue;
    const visto = Date.parse(entrada?.v ?? entrada?.p ?? "");
    if (!Number.isNaN(visto) && ahoraMs - visto <= olvido) vigentes[euvd] = entrada;
  }

  await escribirJson(registroVistas, {
    sembrado: estado.sembrado ?? ahoraIso,
    ids: vigentes,
  });

  if (primeraRevision) {
    // La última entrada, que es la marca de la que cuelga todo lo demás: lo que
    // llegue por delante de esta es lo que se ingiere en la revisión siguiente.
    const ultima = filas.reduce(
      (a, f) => (a && String(a.fecha) >= String(f.fecha) ? a : f),
      null
    );
    log(
      `Primera revisión: anotadas ${filas.length} entradas sin publicar ninguna. ` +
        (ultima ? `La última es ${ultima.euvd} (${ultima.cve ?? "sin CVE"}), del ${ultima.fecha}. ` : "") +
        "A partir de la pasada siguiente solo entra lo que no esté en esta lista."
    );
    return [];
  }

  log(
    `Registro: ${publicables.length} filas en el feed ` +
      `(${nuevas} nuevas en esta pasada, ${caducadas} retiradas por pasar de ${VENTANA_DIAS} días, ` +
      `${Object.keys(vigentes).length} conocidas en total)`
  );
  return publicables;
}

// ---------------------------------------------------------------- descarga

if (!(await tomarCerrojo())) {
  log("Ya hay otro sync en marcha; no hago nada.");
  process.exit(0);
}

log(RAPIDO ? "Pasada rápida (NVD y EPSS desde caché)" : "Pasada completa");

const ahora = new Date();
const desde = soloFecha(new Date(ahora.getTime() - VENTANA_DIAS * 86400000));
const hasta = soloFecha(ahora);

const registros = new Map();
let totalApi = null;

for (let pagina = 0; pagina < MAX_PAGINAS; pagina++) {
  const url =
    API_SEARCH +
    "?" +
    new URLSearchParams({
      fromDate: desde,
      toDate: hasta,
      fromScore: "0",
      toScore: "10",
      page: String(pagina),
      size: String(PAGE_SIZE),
    });

  const respuesta = await pedir(url);
  if (respuesta === null) {
    log(`Página ${pagina} falló; corto aquí y conservo lo descargado.`);
    break;
  }

  totalApi = respuesta.total ?? totalApi;
  const items = respuesta.items ?? [];
  if (!Array.isArray(items) || items.length === 0) break;

  for (const item of items) {
    const fila = normalizar(item);
    if (fila) registros.set(fila.euvd, fila); // la clave deduplica
  }

  log(`Página ${pagina}: ${items.length} items (acumulado: ${registros.size}${totalApi ? " de " + totalApi : ""})`);

  if (items.length < PAGE_SIZE) break;
  if (totalApi && registros.size >= totalApi) break;
  await dormir(PAUSA_MS);
}

if (registros.size === 0) {
  log("Sin registros. No sobrescribo el JSON anterior.");
  process.exit(1);
}

if (totalApi && registros.size < totalApi) {
  log(
    `AVISO: la EUVD dice ${totalApi} en la ventana y solo tengo ${registros.size}. ` +
      "Sube MAX_PAGINAS o acorta VENTANA_DIAS."
  );
}

// ---------------------------------------------------------------- salida

// El catálogo va antes de construir las filas, para que lo que siembre pase por
// los mismos enriquecidos que lo demás: título de cve.org, CWE y EPSS. Las CWE
// del NVD sí se las pierde —esas se piden por ventana de publicación—, pero la
// fuente principal de CWE es cve.org y el NVD solo es el respaldo.
const entradasKev = await pedirKev();
const vulncheckKev = await pedirVulncheckKev();
await sembrarKev(registros, entradasKev, vulncheckKev);

const filas = [...registros.values()].sort((a, b) =>
  String(b.fecha).localeCompare(String(a.fecha))
); // más recientes primero

await completarMeta(filas);
await completarCwesNvd(filas);
await completarEpss(filas);
completarKev(filas, entradasKev, vulncheckKev);

// Se filtra al final, con las filas ya enriquecidas y en un solo sitio: lo que
// salga de aquí es lo que se publica y lo único de lo que Telegram llega a
// enterarse. Las dos cosas son la misma lista a propósito.
const publicables = await filtrarNuevas(filas, ahora);
const registro = await leerCache(registroVistas);

const salida = {
  generado: new Date().toISOString(),
  ventanaDias: VENTANA_DIAS,
  desdeCero: registro.sembrado ?? null, // cuándo se hizo la primera revisión
  conocidas: Object.keys(registro.ids ?? {}).length, // lo que el feed ya ha visto
  modo: RAPIDO ? "rapido" : "completo",
  desde,
  hasta,
  total: publicables.length,
  totalEnEuvd: totalApi, // lo que la EUVD dice tener en la ventana, sin lo sembrado por KEV
  fueraDeVentana: publicables.filter((f) => f.fueraDeVentana).length,
  fuente: "EU Vulnerability Database (ENISA)",
  fuenteScore: "EU Vulnerability Database (ENISA)",
  fuenteEpss: "EPSS de FIRST",
  fuenteKev: "VulnCheck KEV, más CISA KEV y EU KEV vía EUVD",
  fuenteCwe: "cve.org, con el NVD de respaldo",
  items: publicables,
};

await escribirJson(destino, salida);

log(
  `Escritas ${publicables.length} vulnerabilidades en ${destino} ` +
    `(${RAPIDO ? "pasada rápida" : "pasada completa"})`
);

await notificarTelegram(publicables, registro.sembrado ?? null, vulncheckKev);
