/**
 * Retira del tema de KEV los mensajes que nunca debieron enviarse.
 *
 * De un solo uso. Lo que los mandó fue la poda de .notificado.json, que se
 * quedaba con lo que traía la pasada en vez de con lo que seguía vigente: un
 * catálogo de KEV que no bajaba borraba de golpe cientos de apuntes y a la pasada
 * siguiente esas CVE volvían a contar como no avisadas. Eso ya está arreglado en
 * euvd_sync.mjs; esto solo limpia lo que quedó publicado.
 *
 * A quién se señala: al mensaje que sigue anotado en la sala de KEV, de una fila
 * que entró por el catálogo y no por la ventana, y que se envió más de
 * DIAS_NOTICIA después de que esa CVE entrara en el catálogo. Ese desfase es la
 * firma del fallo: una mudanza legítima a KEV ocurre en la pasada siguiente a que
 * CISA la añada, no ocho meses después. Lo que no cumpla las tres cosas se queda
 * donde está, que ante la duda es mejor un mensaje de más que uno bueno borrado.
 *
 * Sin LIMPIAR_EN_SERIO=1 no borra nada: lista lo que haría y se va.
 *
 * Los mensajes que el estado ya no apunta —si una CVE se reavisó dos veces, solo
 * queda el identificador del último— no se pueden alcanzar: la API de bots no deja
 * leer el historial de un chat. Esos, si los hay, hay que quitarlos a mano.
 */

import { readFile, writeFile, rename } from "node:fs/promises";

const TOKEN = process.env.TELEGRAM_BOT_TOKEN ?? "";
const EN_SERIO = process.env.LIMPIAR_EN_SERIO === "1";

const ESTADO = ".notificado.json";
const FEED = "public/data/cves.json";

// Los mismos que euvd_sync.mjs: el criterio de "esto ya no es noticia" tiene que
// ser el mismo que el que evita que vuelva a pasar.
const DIAS_NOTICIA = 7;
const PAUSA_MS = 3500; // el límite del grupo, ~20 llamadas por minuto

const log = (msg) => process.stdout.write(`[${new Date().toISOString().replace(/\.\d+Z$/, "Z")}] ${msg}\n`);
const dormir = (ms) => new Promise((r) => setTimeout(r, ms));

if (!TOKEN) {
  log("Sin TELEGRAM_BOT_TOKEN: no hay nada que hacer.");
  process.exit(1);
}

const estado = JSON.parse(await readFile(ESTADO, "utf8"));
const feed = JSON.parse(await readFile(FEED, "utf8"));

const avisadas = estado.avisadas ?? {};
const filas = new Map((feed.items ?? []).map((f) => [f.euvd, f]));

log(`${Object.keys(avisadas).length} apuntes en el estado, ${filas.size} filas en el feed.`);

const ahora = new Date().toISOString();
const sospechosos = [];
let sinFila = 0;

for (const [euvd, apunte] of Object.entries(avisadas)) {
  if (!apunte || typeof apunte !== "object") continue;
  if (apunte.sala !== "kev" || !apunte.enviada) continue;
  if (apunte.mensaje == null || !apunte.chat) continue;

  const fila = filas.get(euvd);
  if (!fila) {
    // Sin la fila no se puede saber si el aviso fue legítimo. Se deja en paz.
    sinFila++;
    continue;
  }

  if (fila.fueraDeVentana !== true) continue; // publicada dentro de la ventana: es reciente

  const entrada = Date.parse(fila.kev?.fecha ?? "");
  const enviado = Date.parse(apunte.fecha ?? "");
  if (Number.isNaN(entrada) || Number.isNaN(enviado)) continue;

  const retraso = (enviado - entrada) / 86400000;
  if (retraso <= DIAS_NOTICIA) continue; // se avisó al entrar en el catálogo: correcto

  sospechosos.push({ euvd, apunte, fila, retraso });
}

sospechosos.sort((a, b) => b.retraso - a.retraso);

log(
  `${sospechosos.length} mensajes a retirar del tema de KEV` +
    (sinFila ? ` (${sinFila} apuntes sin fila en el feed, intactos)` : "")
);

const linea = (s) =>
  `  ${s.euvd}  ${s.fila.cve ?? ""}  en KEV desde ${String(s.fila.kev?.fecha ?? "?").slice(0, 10)}` +
  `, publicada ${String(s.fila.fecha ?? "?").slice(0, 10)}` +
  `, avisada ${String(s.apunte.fecha).slice(0, 10)} (${Math.round(s.retraso)} días tarde)`;

for (const s of sospechosos.slice(0, 40)) log(linea(s));
if (sospechosos.length > 40) log(`  … y ${sospechosos.length - 40} más`);

if (!EN_SERIO) {
  log("Ensayo: no he borrado nada. Con LIMPIAR_EN_SERIO=1 se borran de verdad.");
  process.exit(0);
}

if (sospechosos.length === 0) {
  log("Nada que borrar.");
  process.exit(0);
}

/** Escritura atómica, igual que el sync: el estado no puede quedarse a medias. */
const guardar = async () => {
  await writeFile(ESTADO + ".tmp", JSON.stringify(estado), "utf8");
  await rename(ESTADO + ".tmp", ESTADO);
};

let borrados = 0;
let fallidos = 0;
let reencolados = 0; // tope de reintentos por 429, para no dar vueltas sin fin

for (const [i, s] of sospechosos.entries()) {
  if (i > 0) await dormir(PAUSA_MS);

  let r;
  try {
    const respuesta = await fetch(`https://api.telegram.org/bot${TOKEN}/deleteMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: s.apunte.chat, message_id: s.apunte.mensaje }),
      signal: AbortSignal.timeout(20000),
    });
    r = await respuesta.json().catch(() => null);
  } catch (e) {
    log(`  ${s.euvd}: la llamada falló (${e.message}); lo dejo para otra vez.`);
    fallidos++;
    continue;
  }

  // 429: Telegram dice cuánto callar. Aquí no hay prisa, así que se espera y se
  // reintenta esa misma, en vez de cortar como hace el sync.
  const esperar = Number(r?.parameters?.retry_after ?? 0);
  if (esperar > 0) {
    log(`  me pide esperar ${esperar} s; espero.`);
    await dormir((esperar + 1) * 1000);
    if (++reencolados <= 50) sospechosos.push(s); // al final de la cola
    else fallidos++;
    continue;
  }

  // "message to delete not found" cuenta como hecho: el mensaje ya no está, que
  // es justo lo que se quería.
  const noEstaba = /not found/i.test(String(r?.description ?? ""));
  if (r?.ok !== true && !noEstaba) {
    log(`  ${s.euvd}: no pude borrarlo — ${r?.description ?? "sin motivo"}`);
    fallidos++;
    continue;
  }

  // El apunte se queda, sin identificador de mensaje: la fila sigue contando como
  // conocida —así el sync no la trata como un primer aviso— pero ya no apunta a
  // un mensaje que no existe, que es lo que haría fallar la próxima edición.
  estado.avisadas[s.euvd] = {
    sala: s.apunte.sala,
    fecha: s.apunte.fecha,
    visto: ahora,
    enviada: false,
    firma: s.apunte.firma,
  };

  borrados++;
  if (borrados % 20 === 0) {
    await guardar();
    log(`  ${borrados}/${sospechosos.length} borrados`);
  }
}

await guardar();
log(`Listo: ${borrados} mensajes retirados del tema de KEV${fallidos ? `, ${fallidos} no pude` : ""}.`);
