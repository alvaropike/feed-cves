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
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------- configuración

const API_SEARCH = "https://euvdservices.enisa.europa.eu/api/search";
const API_CVE = "https://cveawg.mitre.org/api/cve/"; // registros oficiales de cve.org
const API_KEV = "https://euvdservices.enisa.europa.eu/api/kev/dump"; // CISA KEV + EU KEV
const VENTANA_DIAS = 14; // cuántos días hacia atrás pedir
const PAGE_SIZE = 100; // máximo que admite la API
// La ventana de 14 días ronda las 5.000 vulnerabilidades, así que 25 páginas se
// quedaban con la mitad —y no con la mitad más reciente, sino con las que
// devolviera la API—. El tope sigue existiendo por seguridad, pero ahora holgado.
const MAX_PAGINAS = 60; // tope de seguridad: 60 * 100 = 6.000 registros
const PAUSA_MS = 400; // 0,4 s entre peticiones, para no castigar la API
const TIMEOUT_MS = 30000;
const CONCURRENCIA_TITULOS = 6; // peticiones simultáneas a cve.org

const API_EPSS = "https://api.first.org/data/v1/epss"; // probabilidad de explotación (FIRST)
const EPSS_TANDA = 100; // máximo de CVE que admite una petición a FIRST
const EPSS_PAUSA_MS = 300;

const API_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CLAVE = process.env.NVD_API_KEY ?? ""; // opcional: sube el límite a 50 peticiones/30 s
const NVD_PAGE = 2000; // máximo que admite la API del NVD
const NVD_MAX_PAGINAS = 15; // tope de seguridad: 15 * 2.000 = 30.000 CVE
const NVD_MARGEN_DIAS = 30; // se pide más ventana de la necesaria; ver completarScores()
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

const TG_MAX_MENSAJES = 12; // por sala y pasada; lo que sobre se avisa en la siguiente
// El límite que manda no es el del chat sino el del grupo: unos 20 mensajes por
// minuto. Con las seis salas montadas como temas de un mismo grupo, los 1,2 s de
// antes iban a ~50/min contra ese tope y Telegram devolvía 429 (visto el
// 2026-09-08 a las 04:35). 3,5 s deja el ritmo en ~17/min, por debajo del límite.
const TG_PAUSA_MS = 3500;

/**
 * Modo rápido: el listado de la EUVD, los títulos y CWE nuevos de cve.org y el
 * KEV; el CVSS del NVD y la EPSS se leen de la caché en vez de pedirse.
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
const cacheScores = join(AQUI, "public", "data", "scores_nvd.json");
const cacheEpss = join(AQUI, "public", "data", "epss.json");
// Fuera de data/: ese directorio se publica y esto es estado interno, no un dato del feed.
const estadoTelegram = join(AQUI, ".notificado.json");

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

// ---------------------------------------------------------------- CVSS y CWE del NVD

const fechaNvd = (d) => d.toISOString().slice(0, 19) + ".000";

/**
 * Del bloque `metrics` del NVD saca la métrica CVSS más moderna disponible,
 * prefiriendo la primaria (la del propio NIST o del CNA) sobre las secundarias.
 */
function metricaNvd(metrics) {
  for (const clave of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const lista = metrics?.[clave];
    if (!Array.isArray(lista) || lista.length === 0) continue;

    const elegida = lista.find((m) => m?.type === "Primary") ?? lista[0];
    const datos = elegida?.cvssData;
    if (datos?.baseScore == null) continue;

    return {
      score: Number(datos.baseScore),
      cvss: datos.version ?? null,
      vector: datos.vectorString ?? null,
    };
  }
  return null; // CVE recibida pero sin analizar todavía ("Awaiting Analysis")
}

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
 * Baja del NVD todas las CVE publicadas en un rango de fechas, paginando.
 * @returns {Promise<Record<string, {score:number|null,cvss:string|null,vector:string|null,cwes:{id:string,nombre:string|null}[]}>>}
 */
async function pedirScoresNvd(desdeIso, hastaIso) {
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
      log("El NVD falló; me quedo con las puntuaciones que ya tenga.");
      break;
    }

    const vulns = respuesta.vulnerabilities ?? [];
    if (!Array.isArray(vulns) || vulns.length === 0) break;

    for (const entrada of vulns) {
      const id = entrada?.cve?.id;
      if (typeof id !== "string") continue;

      const metrica = metricaNvd(entrada?.cve?.metrics);
      const cwes = cwesDeNvd(entrada?.cve?.weaknesses);
      // Guardamos la entrada aunque solo traiga CWE: el NVD tarda en puntuar,
      // pero la debilidad suele venir desde el primer momento.
      if (metrica || cwes.length) salida[id] = { ...(metrica ?? {}), cwes };
    }

    const total = respuesta.totalResults ?? 0;
    log(`NVD página ${pagina}: ${vulns.length} CVE (con CVSS acumuladas: ${Object.keys(salida).length})`);

    if ((pagina + 1) * NVD_PAGE >= total) break;
    await dormir(NVD_PAUSA_MS);
  }

  return salida;
}

/**
 * Sustituye la puntuación de la EUVD por la del NVD cuando esta existe.
 *
 * Se pide por rango de fechas en vez de CVE a CVE porque la API del NVD admite
 * 5 peticiones cada 30 s sin clave (50 con `NVD_API_KEY`): así son ~9 páginas para
 * la ventana entera, mientras que ir uno por uno serían horas. El rango va con
 * NVD_MARGEN_DIAS de margen hacia atrás porque la fecha de publicación en el NVD
 * no tiene por qué coincidir con la de la EUVD. Lo que aun así se quede fuera
 * conserva la puntuación de la EUVD, marcada en `origenScore`.
 */
async function completarScores(filas) {
  const hasta = new Date();
  const desde = new Date(hasta.getTime() - (VENTANA_DIAS + NVD_MARGEN_DIAS) * 86400000);

  const cache = await leerCache(cacheScores);
  // En modo rápido no se pregunta al NVD: es la fase más lenta con diferencia y
  // el enriquecimiento no va a cambiar en quince minutos.
  const frescas = RAPIDO ? {} : await pedirScoresNvd(fechaNvd(desde), fechaNvd(hasta));
  const scores = { ...cache, ...frescas }; // lo recién bajado manda sobre la caché

  const vigentes = {};
  let conNvd = 0;
  for (const fila of filas) {
    const nvd = fila.cve ? scores[fila.cve] : null;
    if (!nvd) continue;

    if (nvd.score != null) {
      fila.score = nvd.score;
      fila.severidad = severidad(nvd.score);
      fila.cvss = nvd.cvss ?? fila.cvss;
      fila.vector = nvd.vector ?? fila.vector;
      fila.origenScore = "nvd";
      conNvd++;
    }
    // El NVD solo completa las CWE que cve.org no haya dado: allí vienen con nombre.
    if (nvd.cwes?.length) fila.cwes = fusionarCwes(fila.cwes, nvd.cwes);

    vigentes[fila.cve] = nvd;
  }

  // Igual que con los títulos: la caché se queda solo con lo que sigue en ventana.
  await escribirJson(cacheScores, vigentes);
  log(`${conNvd} de ${filas.length} filas con CVSS del NVD${RAPIDO ? " (de caché)" : ""}`);
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
 * Marca las filas que están en el catálogo de vulnerabilidades explotadas: CISA
 * KEV y EU KEV, que la EUVD consolida y sirve de una vez en `/api/kev/dump`.
 *
 * Es el complemento de la EPSS, no un duplicado: la EPSS estima la probabilidad
 * de que alguien la explote, el KEV dice que ya lo está haciendo. Y no se parecen
 * —de las que caen en KEV, la mayoría anda por debajo del 1 % de EPSS—, así que
 * ordenar por EPSS las entierra. Una sola petición, sin paginar.
 */
async function completarKev(filas) {
  const dump = await pedir(API_KEV);
  const entradas = Array.isArray(dump) ? dump : dump?.items;

  if (!Array.isArray(entradas)) {
    log("KEV: no pude leer el catálogo; las filas se quedan sin marcar.");
    return;
  }

  const porCve = new Map();
  const porEuvd = new Map();
  for (const e of entradas) {
    if (typeof e?.cveId === "string") porCve.set(e.cveId, e);
    if (typeof e?.euvdId === "string") porEuvd.set(e.euvdId, e);
  }

  let marcadas = 0;
  for (const fila of filas) {
    const kev = (fila.cve && porCve.get(fila.cve)) || porEuvd.get(fila.euvd);
    if (!kev) continue;

    fila.kev = {
      fecha: typeof kev.dateAdded === "string" ? kev.dateAdded : null,
      fuentes: Array.isArray(kev.sources) ? kev.sources : [],
    };
    marcadas++;
  }

  log(`${marcadas} de ${filas.length} filas explotadas activamente (KEV tiene ${entradas.length})`);
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
    score,
    severidad: severidad(score),
    // La EUVD manda 0 cuando no hay CVSS: eso no es una puntuación, es un hueco.
    origenScore: score != null && score > 0 ? "euvd" : null, // lo pisa completarScores()
    cvss: item.baseScoreVersion ?? null,
    vector: item.baseScoreVector ?? null,
    cwes: [], // lo rellenan completarMeta() y completarScores()
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
 * Las salas, de menos a más prioridad. Este orden decide dos cosas: a qué sala
 * va una fila que encaja en varias —KEV manda sobre la puntuación— y qué cuenta
 * como escalar, porque solo se reavisa hacia arriba.
 */
const TG_ORDEN = ["sin_puntuar", "baja", "media", "alta", "critica", "kev"];


const prioridadSala = (sala) => TG_ORDEN.indexOf(sala);

/** Cada fila va a una sola sala: la de KEV si consta explotada, si no la de su severidad. */
const salaDe = (fila) => (fila.kev ? "kev" : fila.severidad);

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

/** Los catálogos se identifican con su nombre, no con la clave de la API. */
const TG_FUENTE_KEV = { cisa_kev: "CISA KEV", eukev_kev: "EU KEV" };

// La descripción va en una cita: por encima de TG_DESC_PLEGABLE, Telegram la
// pliega y deja el resto del mensaje a la vista. El tope duro existe porque hay
// descripciones de 4.000 caracteres y un mensaje entero no puede pasar de 4.096.
const TG_DESC_PLEGABLE = 300;
const TG_DESC_MAX = 3000;

const TG_CWE_VISIBLES = 3; // el mismo tope que la tabla; el resto va como "+n"

/**
 * Un mensaje por vulnerabilidad, en cuatro bloques: cabecera con lo que se ve en
 * la notificación del móvil (criticidad, puntuación e identificador), título,
 * la alerta de explotación si la hay, los datos etiquetados y los enlaces.
 *
 * El identificador va en <code> para que Telegram lo ponga en monoespaciada y
 * se pueda copiar tocándolo, que es lo primero que se hace con un CVE.
 *
 * `previa` solo llega cuando es un reaviso por escalada, y entonces el mensaje
 * abre diciéndolo: en la sala de KEV, la mitad de los mensajes son CVE de las
 * que ya se avisó hace días, y sin ese aviso parecen recién publicadas.
 */
function mensajeTelegram(fila, previa = null) {
  const lineas = [];

  if (previa) {
    const antes = TG_ETIQUETA_SALA[previa.sala] ?? previa.sala;
    const cuando = typeof previa.fecha === "string" ? ` on ${previa.fecha.slice(0, 10)}` : "";
    lineas.push(`\u{2B06}\u{FE0F} <b>Escalated</b> — previously reported as ${antes}${cuando}`, "");
  }

  const marca = TG_MARCA[fila.severidad] ?? TG_MARCA.sin_puntuar;
  const puntuacion = fila.score != null ? ` · CVSS <b>${fila.score.toFixed(1)}</b>` : "";
  lineas.push(`${marca}${puntuacion} · <code>${escaparHtml(fila.cve ?? fila.euvd)}</code>`);

  // La descripción trae saltos de línea a media frase, así que se normaliza.
  const descripcion = String(fila.descripcion ?? "").replace(/\s+/g, " ").trim();

  // Cuando cve.org no tiene título, `nombre` es el primer trozo de la propia
  // descripción —una de cada cuatro filas—: repetirlo sería enseñar dos veces la
  // misma frase, así que ahí manda la descripción, que además viene entera.
  const titulo = fila.nombre === "Sin descripción" ? "" : String(fila.nombre ?? "");
  if (titulo && !descripcion.startsWith(titulo.replace(/…$/, "").trim())) {
    lineas.push(`<b>${escaparHtml(titulo)}</b>`);
  }

  if (fila.kev) {
    const fuentes = (fila.kev.fuentes ?? [])
      .map((f) => TG_FUENTE_KEV[f] ?? String(f).toUpperCase())
      .join(" · ");
    const desde = typeof fila.kev.fecha === "string" ? `, added ${fila.kev.fecha.slice(0, 10)}` : "";
    lineas.push("", `\u{26A0}\u{FE0F} <b>Actively exploited</b>${fuentes ? ` — ${escaparHtml(fuentes)}` : ""}${desde}`);
  }

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

  if (fila.vendor) datos.push(`<b>Vendor:</b> ${escaparHtml(fila.vendor)}`);
  if (fila.producto && fila.producto !== fila.vendor) {
    datos.push(`<b>Product:</b> ${escaparHtml(fila.producto)}`);
  }

  if (fila.epss != null) {
    const probabilidad = (fila.epss * 100).toFixed(1);
    const percentil =
      fila.epssPercentil != null ? ` (percentile ${Math.round(fila.epssPercentil * 100)})` : "";
    datos.push(`<b>EPSS:</b> ${probabilidad}%${percentil}`);
  }

  // Enlazadas a cwe.mitre.org, igual que en la tabla, y con el mismo tope de tres
  // visibles y un "+n" con el resto: en un mensaje de móvil, seis identificadores
  // seguidos ocupan más que todo lo demás junto.
  const cwes = (fila.cwes ?? []).map((c) => c?.id).filter((id) => /^CWE-\d+$/.test(id));
  if (cwes.length) {
    const enlazadas = cwes
      .slice(0, TG_CWE_VISIBLES)
      .map((id) => `<a href="https://cwe.mitre.org/data/definitions/${id.slice(4)}.html">${id}</a>`)
      .join(", ");
    const resto = cwes.length - TG_CWE_VISIBLES;
    datos.push(`<b>CWE:</b> ${enlazadas}${resto > 0 ? ` +${resto}` : ""}`);
  }

  if (fila.origenScore === "euvd") datos.push("<b>Score:</b> EUVD, pending NVD analysis");
  if (fila.fecha) datos.push(`<b>Published:</b> ${fila.fecha.slice(0, 10)}`);

  if (datos.length) lineas.push("", ...datos);

  const enlaces = [];
  if (fila.enlace) enlaces.push(`<a href="${escaparHtml(fila.enlace)}">NVD</a>`);
  if (fila.cve) {
    enlaces.push(`<a href="https://www.cve.org/CVERecord?id=${escaparHtml(fila.cve)}">CVE Record</a>`);
  }
  if (enlaces.length) lineas.push("", enlaces.join(" · "));

  return lineas.join("\n");
}

/** Devuelve si se envió y, cuando Telegram pide esperar (429), cuántos segundos. */
async function telegramEnviar(destino, texto) {
  const { chat, hilo } = partirDestino(destino);

  try {
    const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chat,
        ...(hilo != null ? { message_thread_id: hilo } : {}),
        text: texto,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    const json = await r.json().catch(() => null);
    if (r.ok && json?.ok === true) return { enviado: true, esperar: 0 };

    log(`Telegram: HTTP ${r.status} en ${destino} ${json?.description ?? ""}`.trimEnd());
    return { enviado: false, esperar: Number(json?.parameters?.retry_after ?? 0) };
  } catch (e) {
    log(`Telegram: petición fallida (${e.message})`);
    return { enviado: false, esperar: 0 };
  }
}

/**
 * Avisa por Telegram, cada vulnerabilidad a la sala que le toca.
 *
 * Lo que decide si algo se avisa no es la fecha sino .notificado.json, donde
 * queda a qué sala fue cada una. La ventana se solapa entre pasadas y los datos
 * llegan tarde —una CVE entra sin CVSS y recibe un 9.8 tres pasadas después—,
 * así que filtrar por fecha se dejaría justo lo que más importa.
 *
 * Y por eso mismo se reavisa cuando algo escala de sala: una que se avisó como
 * alta y hoy consta en KEV es una noticia, no un duplicado. Solo hacia arriba;
 * que el NVD rebaje una nota no merece un mensaje.
 *
 * Las filas sin sala configurada se anotan igual, sin enviar. Así, el día que
 * montes la sala de medias, no te caen encima las 1.700 de la ventana: solo
 * llega lo que aparezca a partir de entonces.
 *
 * La primera ejecución no manda nada: siembra el fichero con lo que ya hay.
 *
 * Va después de escribir el JSON a propósito: que Telegram no conteste no puede
 * dejar la web sin actualizar.
 */
async function notificarTelegram(filas) {
  const salasConfiguradas = Object.values(TG_SALAS).filter(Boolean).length;

  if (!TG_TOKEN || (!TG_CHAT && salasConfiguradas === 0)) {
    log("Telegram: sin TELEGRAM_BOT_TOKEN o sin ningún chat configurado, no aviso.");
    return;
  }

  const estado = await leerCache(estadoTelegram);
  const previas = estado.avisadas && typeof estado.avisadas === "object" ? estado.avisadas : {};

  // El formato viejo guardaba `euvd: fecha` en vez de `euvd: {sala, fecha}`. Se
  // reconstruye entero y sin avisar, como una siembra: reaprovecharlo mandaría un
  // reaviso de escalada por cada fila que antes no tenía sala anotada.
  const formatoViejo = Object.values(previas).some((v) => typeof v !== "object" || v === null);
  const primeraVez = typeof estado.sembrado !== "string";

  // La poda: nos quedamos con lo que sigue dentro de la ventana, como las demás
  // cachés, para que el fichero no crezca sin fin.
  const vigentes = {};
  for (const fila of filas) {
    if (Object.hasOwn(previas, fila.euvd)) vigentes[fila.euvd] = previas[fila.euvd];
  }

  if (primeraVez || formatoViejo) {
    const ahora = new Date().toISOString();
    for (const fila of filas) vigentes[fila.euvd] = { sala: salaDe(fila), fecha: ahora, enviada: false };

    await escribirJson(estadoTelegram, { sembrado: estado.sembrado ?? ahora, avisadas: vigentes });
    log(
      `Telegram: ${primeraVez ? "primera ejecución" : "estado en formato antiguo"}, siembro ` +
        `${filas.length} vulnerabilidades sin avisar. A partir de la siguiente pasada solo llega lo nuevo.`
    );
    return;
  }

  // Nuevas y escaladas. Las que no tengan sala montada se anotan aquí mismo y no
  // vuelven a mirarse mientras no suban de sala.
  const ahora = new Date().toISOString();
  const candidatas = [];

  for (const fila of filas) {
    const sala = salaDe(fila);
    const previa = vigentes[fila.euvd] ?? null;
    if (previa && prioridadSala(sala) <= prioridadSala(previa.sala)) continue;

    const destino = destinoDe(sala, fila);
    if (!destino) {
      vigentes[fila.euvd] = { sala, fecha: ahora, enviada: false };
      continue;
    }

    candidatas.push({ fila, sala, destino, previa: previa?.enviada ? previa : null });
  }

  if (candidatas.length === 0) {
    log("Telegram: nada nuevo que avisar.");
    await escribirJson(estadoTelegram, { sembrado: estado.sembrado, avisadas: vigentes });
    return;
  }

  // Por sala y luego por puntuación: si un día hay atasco, lo que ya se está
  // explotando sale delante.
  candidatas.sort(
    (a, b) => prioridadSala(b.sala) - prioridadSala(a.sala) || (b.fila.score ?? 0) - (a.fila.score ?? 0)
  );

  const enviadas = {};
  let total = 0;
  let cortado = false;

  for (const { fila, sala, destino, previa } of candidatas) {
    // El tope es por sala: el límite de Telegram es por chat, así que un atasco
    // en medias no tiene por qué retrasar el aviso de una crítica.
    const cupo = (enviadas[sala] ?? 0) + 1;
    if (cupo > TG_MAX_MENSAJES) continue; // se queda sin marcar: sale en la siguiente pasada

    if (total > 0) await dormir(TG_PAUSA_MS);
    const { enviado, esperar } = await telegramEnviar(destino, mensajeTelegram(fila, previa));

    if (enviado) {
      vigentes[fila.euvd] = { sala, fecha: ahora, enviada: true };
      enviadas[sala] = cupo;
      total++;
    } else if (esperar > 0) {
      // 429: Telegram dice cuánto callar. Cortamos y lo retomamos en la pasada
      // siguiente; lo no enviado se queda sin marcar, así que no se pierde.
      log(`Telegram: me pide esperar ${esperar} s; lo dejo para la siguiente pasada.`);
      cortado = true;
      break;
    }
  }

  await escribirJson(estadoTelegram, { sembrado: estado.sembrado, avisadas: vigentes });

  const desglose = Object.entries(enviadas)
    .map(([sala, n]) => `${sala} ${n}`)
    .join(", ");
  const cola = candidatas.length - total;
  log(
    `Telegram: ${total} avisos enviados${desglose ? ` (${desglose})` : ""}` +
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

const filas = [...registros.values()].sort((a, b) =>
  String(b.fecha).localeCompare(String(a.fecha))
); // más recientes primero

await completarMeta(filas);
await completarScores(filas);
await completarEpss(filas);
await completarKev(filas);

const salida = {
  generado: new Date().toISOString(),
  ventanaDias: VENTANA_DIAS,
  modo: RAPIDO ? "rapido" : "completo",
  desde,
  hasta,
  total: filas.length,
  totalEnEuvd: totalApi,
  fuente: "EU Vulnerability Database (ENISA)",
  fuenteScore: "NVD (NIST), con la EUVD de respaldo",
  fuenteEpss: "EPSS de FIRST",
  fuenteKev: "CISA KEV y EU KEV, vía EUVD",
  fuenteCwe: "cve.org, con el NVD de respaldo",
  items: filas,
};

await escribirJson(destino, salida);

log(
  `Escritas ${filas.length} vulnerabilidades en ${destino} ` +
    `(${RAPIDO ? "pasada rápida" : "pasada completa"})`
);

await notificarTelegram(filas);
