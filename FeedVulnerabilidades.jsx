import { useState, useEffect, useMemo, useRef, useDeferredValue, useCallback } from "react";

/**
 * Tabla de vulnerabilidades publicadas recientemente.
 *
 * Lee el JSON que genera euvd_sync.php por cron: el listado y la puntuación CVSS
 * vienen de la EUVD, el nombre de cada fila es el título oficial de cve.org, las
 * CWE salen del registro de cve.org y del NVD, la EPSS del modelo de FIRST y la
 * marca de explotación activa de los catálogos KEV. Si no encuentra el JSON,
 * carga un puñado de filas de ejemplo para que la interfaz sea navegable
 * mientras montas el backend.
 *
 * Sin dependencias: estilos embebidos, nada de Tailwind ni librerías de tabla.
 */

const RUTA_DATOS = "./data/cves.json";
const POR_PAGINA = 25;

/**
 * Los colores no son literales sino variables CSS porque hay dos temas: el
 * naranja y el amarillo que se leen bien sobre el fondo oscuro desaparecen sobre
 * blanco. Cada tema redefine la variable; el JSX no se entera.
 */
const SEVERIDADES = {
  critica: { etiqueta: "Critical", color: "var(--sev-critica)", orden: 4 },
  alta: { etiqueta: "High", color: "var(--sev-alta)", orden: 3 },
  media: { etiqueta: "Medium", color: "var(--sev-media)", orden: 2 },
  baja: { etiqueta: "Low", color: "var(--sev-baja)", orden: 1 },
  sin_puntuar: { etiqueta: "Unscored", color: "var(--sev-nula)", orden: 0 },
};

const ORDEN_SEVERIDAD = ["critica", "alta", "media", "baja", "sin_puntuar"];

// CWE que caben en la celda antes de resumir el resto en un "+n".
const CWE_VISIBLES = 3;

/**
 * Las columnas de la tabla, que son también los criterios de ordenación: la
 * cabecera de cada una ordena por ella. `porDefecto` es la dirección del primer
 * clic —descendente en lo numérico, porque lo interesante es lo alto y lo
 * reciente; ascendente en el texto, que se lee de la A a la Z— y `orden` son las
 * etiquetas del desplegable que queda en móvil, donde no hay cabecera que pulsar.
 */
const COLUMNAS = [
  {
    clave: "cve",
    etiqueta: "CVE",
    tipo: "texto",
    porDefecto: "asc",
    valor: (v) => v.cve ?? v.euvd,
    orden: { asc: "CVE (A-Z)", desc: "CVE (Z-A)" },
  },
  {
    clave: "nombre",
    etiqueta: "Name",
    tipo: "texto",
    porDefecto: "asc",
    valor: (v) => v.nombre,
    orden: { asc: "Name (A-Z)", desc: "Name (Z-A)" },
  },
  {
    clave: "vendor",
    etiqueta: "Vendor",
    tipo: "texto",
    porDefecto: "asc",
    valor: (v) => v.vendor,
    orden: { asc: "Vendor (A-Z)", desc: "Vendor (Z-A)" },
  },
  {
    clave: "cwe",
    etiqueta: "CWE",
    tipo: "numero",
    porDefecto: "asc",
    valor: (v) => numeroCwe(v.cwes?.[0]?.id),
    orden: { asc: "CWE (lowest first)", desc: "CWE (highest first)" },
  },
  {
    clave: "score",
    etiqueta: "Severity",
    tipo: "numero",
    porDefecto: "desc",
    // La EUVD manda baseScore: 0 cuando nadie la ha puntuado. Ese 0 no es una
    // puntuación baja, es un hueco: si no, ordenar de menor a mayor pondría
    // primero justo las filas de las que no se sabe nada.
    valor: (v) => (v.score > 0 ? v.score : null),
    orden: { desc: "Highest CVSS", asc: "Lowest CVSS" },
  },
  {
    clave: "epss",
    etiqueta: "EPSS",
    tipo: "numero",
    porDefecto: "desc",
    valor: (v) => v.epss,
    titulo: "Probability of exploitation in the next 30 days (EPSS by FIRST)",
    orden: { desc: "Highest EPSS", asc: "Lowest EPSS" },
  },
  {
    clave: "fecha",
    etiqueta: "Date",
    tipo: "fecha",
    porDefecto: "desc",
    valor: (v) => v.fecha,
    orden: { desc: "Newest first", asc: "Oldest first" },
  },
];

const ORDEN_INICIAL = { campo: "fecha", dir: "desc" };

const KEV_COLOR = "var(--kev)";

const KEV_FUENTES = { cisa_kev: "CISA KEV", eukev_kev: "EU KEV" };

const nombreFuenteKev = (f) => KEV_FUENTES[f] ?? f;

const TOP_N = 10;

/**
 * Prioridad de una vulnerabilidad: qué mirar primero de los últimos 14 días.
 *
 * Dos escalones. Arriba lo que consta en KEV, porque ahí la explotación no es una
 * estimación sino un hecho; entre esas ordena la EPSS, que ahí ya no mide "si
 * pasará" sino cuánta actividad hay, y el CVSS desempata. Debajo, el resto por
 * EPSS × impacto: lo probable que es por lo que cuesta si pasa. Sin EPSS o sin
 * CVSS no hay con qué priorizar y la fila se va al final.
 *
 * Ninguna de las dos señales sola sirve: por CVSS hay cientos empatadas en 10.0
 * y por EPSS se hunden 13 de las 14 que ya se están explotando.
 */
function prioridad(v) {
  const impacto = v.score > 0 ? v.score / 10 : null;

  if (v.kev) return { escalon: 2, peso: v.epss ?? 0, desempate: impacto ?? 0 };
  if (v.epss == null || impacto == null) return { escalon: 0, peso: 0, desempate: 0 };
  return { escalon: 1, peso: v.epss * impacto, desempate: impacto };
}

function porPrioridad(a, b) {
  const pa = prioridad(a);
  const pb = prioridad(b);
  if (pa.escalon !== pb.escalon) return pb.escalon - pa.escalon;
  if (pb.peso !== pa.peso) return pb.peso - pa.peso;
  if (pb.desempate !== pa.desempate) return pb.desempate - pa.desempate;
  return String(b.fecha).localeCompare(String(a.fecha));
}

/** "CWE-1284" -> 1284, para poder ordenar la columna por número y no por texto. */
function numeroCwe(id) {
  const n = Number(String(id ?? "").replace("CWE-", ""));
  return Number.isFinite(n) ? n : null;
}

const vacio = (x) => x == null || x === "";

/**
 * Comparador de una columna. Los huecos —sin CVSS, sin EPSS, sin fabricante— se
 * van siempre al final, se ordene como se ordene: si subieran al invertir la
 * dirección, la primera página se llenaría de filas sin el dato que has pedido.
 * A igualdad, desempata la fecha, que es lo que más se espera en un feed.
 */
function comparador({ tipo, valor }, dir) {
  const signo = dir === "asc" ? 1 : -1;

  return (a, b) => {
    const x = valor(a);
    const y = valor(b);

    if (vacio(x) || vacio(y)) {
      if (vacio(x) && vacio(y)) return String(b.fecha).localeCompare(String(a.fecha));
      return vacio(x) ? 1 : -1;
    }

    const peso =
      tipo === "numero"
        ? x - y
        : tipo === "fecha"
        ? String(x).localeCompare(String(y))
        : String(x).localeCompare(String(y), "en", { numeric: true, sensitivity: "base" });

    return peso !== 0 ? signo * peso : String(b.fecha).localeCompare(String(a.fecha));
  };
}

/**
 * Tramos de EPSS. Es una probabilidad de explotación a 30 días, no una gravedad:
 * el 0,1 % de arriba del catálogo pasa del 10 %, así que los cortes van bajos a
 * propósito. Un 1 % ya deja a una CVE por encima de la gran mayoría.
 */
const EPSS_TRAMOS = [
  { min: 0.5, etiqueta: "Exploitation very likely", color: "var(--sev-critica)" },
  { min: 0.1, etiqueta: "Exploitation likely", color: "var(--sev-alta)" },
  { min: 0.01, etiqueta: "Above average", color: "var(--sev-media)" },
  { min: 0, etiqueta: "Exploitation unlikely", color: "var(--sev-nula)" },
];

const EJEMPLO = {
  generado: null,
  demo: true,
  items: [
    {
      euvd: "EUVD-0000-0001",
      cve: "CVE-0000-00001",
      nombre: "Sample: Remote code execution in template parser via crafted include",
      vendor: "Sample vendor",
      producto: "Sample product",
      score: 9.8,
      severidad: "critica",
      cvss: "3.1",
      cwes: [{ id: "CWE-94", nombre: "Improper Control of Generation of Code" }],
      epss: 0.4212,
      epssPercentil: 0.9741,
      origenEpss: "first",
      kev: { fecha: "2026-09-05", fuentes: ["cisa_kev"] },
      fecha: "2026-09-05T09:14:00Z",
    },
    {
      euvd: "EUVD-0000-0002",
      cve: "CVE-0000-00002",
      nombre: "Sample: Local privilege escalation through weak service permissions",
      vendor: "Another vendor",
      producto: "Endpoint agent",
      score: 7.8,
      severidad: "alta",
      cvss: "3.1",
      cwes: [
        { id: "CWE-732", nombre: "Incorrect Permission Assignment for Critical Resource" },
        { id: "CWE-269", nombre: "Improper Privilege Management" },
      ],
      epss: 0.0087,
      epssPercentil: 0.6154,
      origenEpss: "first",
      fecha: "2026-09-05T07:02:00Z",
    },
    {
      euvd: "EUVD-0000-0003",
      cve: "CVE-0000-00003",
      nombre: "Sample: Stored XSS in the administration panel",
      vendor: "Sample vendor",
      producto: "Web portal",
      score: 6.1,
      severidad: "media",
      cvss: "3.1",
      cwes: [{ id: "CWE-79", nombre: "Improper Neutralization of Input During Web Page Generation" }],
      epss: 0.0011,
      epssPercentil: 0.2903,
      origenEpss: "first",
      kev: { fecha: "2026-09-04", fuentes: ["cisa_kev", "eukev_kev"] },
      fecha: "2026-09-04T18:40:00Z",
    },
    {
      euvd: "EUVD-0000-0004",
      cve: "CVE-0000-00004",
      nombre: "Sample: credentials stored in plain text in the billing API",
      vendor: "Third vendor",
      producto: "Billing API",
      score: 3.7,
      severidad: "baja",
      cvss: "3.1",
      cwes: [{ id: "CWE-522", nombre: null }],
      epss: 0.0004,
      epssPercentil: 0.1218,
      origenEpss: "first",
      fecha: "2026-09-04T11:20:00Z",
    },
    {
      euvd: "EUVD-0000-0005",
      cve: null,
      nombre: "Sample: entry with no CVSS score and no cve.org title yet",
      vendor: null,
      producto: null,
      score: null,
      severidad: "sin_puntuar",
      cvss: null,
      cwes: [],
      epss: null,
      epssPercentil: null,
      origenEpss: null,
      fecha: "2026-09-04T08:05:00Z",
    },
  ],
};

function formatearFecha(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

/**
 * La EPSS llega como probabilidad 0-1 y casi siempre es diminuta, así que el
 * número de decimales se ajusta a la magnitud: un 0,04 % redondeado a un decimal
 * sería un 0,0 % y parecería que no hay dato.
 */
function formatearEpss(p) {
  const pct = p * 100;
  if (pct >= 10) return `${pct.toFixed(0)}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return `${pct.toFixed(2)}%`;
}

function tramoEpss(p) {
  return EPSS_TRAMOS.find((t) => p >= t.min) ?? EPSS_TRAMOS[EPSS_TRAMOS.length - 1];
}

/** Texto del tooltip: "1.5% chance … · higher than 97% … · EPSS model by FIRST". */
function descripcionEpss(v) {
  const partes = [`${formatearEpss(v.epss)} chance of exploitation in the next 30 days`];
  if (v.epssPercentil != null) {
    partes.push(`higher than ${(v.epssPercentil * 100).toFixed(0)}% of the catalogue`);
  }
  partes.push(v.origenEpss === "euvd" ? "EUVD figure" : "EPSS model by FIRST");
  return partes.join(" · ");
}

const enlaceCwe = (id) => `https://cwe.mitre.org/data/definitions/${id.replace("CWE-", "")}.html`;

const textoCwe = (cwe) => (cwe.nombre ? `${cwe.id}: ${cwe.nombre}` : cwe.id);

function formatearHora(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * "12 min ago". En un feed que se sincroniza cada cuarto de hora lo que se quiere
 * saber de un vistazo es si el dato está fresco, no a qué hora exacta corrió el
 * cron; la hora exacta se queda en el `title`.
 */
function hace(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const min = Math.round((Date.now() - d.getTime()) / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const horas = Math.round(min / 60);
  if (horas < 24) return `${horas} h ago`;
  return `${Math.round(horas / 24)} d ago`;
}

/* --------------------------------------------------------------------------
 * Estado en la URL
 *
 * Filtros, búsqueda, orden y página viven en la query string. Así una vista se
 * comparte pegando la barra de direcciones —"mira estas tres de Fortinet"— y
 * recargar no te devuelve al principio. Se escribe con replaceState: son ajustes
 * de una misma pantalla, no páginas distintas, y llenar el historial de pasos
 * atrás por cada tecla escrita haría inservible el botón de volver.
 * -------------------------------------------------------------------------- */

function leerUrl() {
  const inicial = {
    busqueda: "",
    filtros: [],
    soloKev: false,
    orden: ORDEN_INICIAL,
    pagina: 0,
    abierta: null,
  };
  if (typeof window === "undefined") return inicial;

  const p = new URLSearchParams(window.location.search);
  const [campo, dir] = String(p.get("sort") ?? "").split(".");
  const columnaValida = COLUMNAS.some((c) => c.clave === campo) && (dir === "asc" || dir === "desc");

  return {
    busqueda: p.get("q") ?? "",
    filtros: String(p.get("sev") ?? "")
      .split(",")
      .filter((c) => ORDEN_SEVERIDAD.includes(c)),
    soloKev: p.get("kev") === "1",
    orden: columnaValida ? { campo, dir } : ORDEN_INICIAL,
    pagina: Math.max(0, (Number(p.get("p")) || 1) - 1),
    abierta: p.get("v") || null,
  };
}

function escribirUrl({ busqueda, filtros, soloKev, orden, pagina, abierta }) {
  if (typeof window === "undefined") return;

  const p = new URLSearchParams();
  if (busqueda.trim()) p.set("q", busqueda.trim());
  if (filtros.length) p.set("sev", filtros.join(","));
  if (soloKev) p.set("kev", "1");
  if (orden.campo !== ORDEN_INICIAL.campo || orden.dir !== ORDEN_INICIAL.dir) {
    p.set("sort", `${orden.campo}.${orden.dir}`);
  }
  if (pagina > 0) p.set("p", String(pagina + 1));
  if (abierta) p.set("v", abierta);

  const cadena = p.toString();
  window.history.replaceState(
    null,
    "",
    `${window.location.pathname}${cadena ? `?${cadena}` : ""}${window.location.hash}`
  );
}

/* --------------------------------------------------------------------------
 * Tema
 * -------------------------------------------------------------------------- */

const CLAVE_TEMA = "euvd-tema";

/** Fondos del `body`: el contenedor no llega a los bordes cuando la lista es corta. */
const FONDO = { dark: "#0f1218", light: "#f5f6f9" };

function temaInicial() {
  if (typeof window === "undefined") return "dark";
  try {
    const guardado = window.localStorage.getItem(CLAVE_TEMA);
    if (guardado === "dark" || guardado === "light") return guardado;
  } catch {
    // localStorage puede estar capado (modo privado, cookies bloqueadas): da igual.
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/* --------------------------------------------------------------------------
 * Piezas sueltas
 * -------------------------------------------------------------------------- */

/**
 * Páginas a pintar: las de los extremos, la actual y sus vecinas, con un salto
 * marcado en medio. Con cuarenta páginas de resultados una tira de cuarenta
 * botones no la usa nadie.
 */
function paginasVisibles(actual, total) {
  const marcadas = [0, total - 1, actual - 1, actual, actual + 1].filter(
    (n) => n >= 0 && n < total
  );
  const unicas = [...new Set(marcadas)].sort((a, b) => a - b);

  const salida = [];
  let previa = null;
  for (const n of unicas) {
    if (previa !== null && n - previa > 1) salida.push("hueco");
    salida.push(n);
    previa = n;
  }
  return salida;
}

/** Copia al portapapeles y confirma en el propio botón durante un segundo y pico. */
function BotonCopiar({ texto, etiqueta = "Copy", titulo }) {
  const [copiado, setCopiado] = useState(false);

  useEffect(() => {
    if (!copiado) return undefined;
    const t = setTimeout(() => setCopiado(false), 1400);
    return () => clearTimeout(t);
  }, [copiado]);

  return (
    <button
      type="button"
      className={copiado ? "euvd-copiar es-hecho" : "euvd-copiar"}
      title={titulo ?? `Copy ${texto}`}
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(texto).then(
          () => setCopiado(true),
          () => {}
        );
      }}
    >
      {copiado ? "Copied" : etiqueta}
    </button>
  );
}

/**
 * Esqueleto de carga. Ocupa el sitio y la forma que tendrá la tabla, así que al
 * llegar los datos nada salta: el JSON son cientos de filas y el salto de un
 * "Loading..." de una línea a una tabla de pantalla y media se nota.
 */
function Esqueleto() {
  return (
    <div className="euvd-tabla" aria-hidden="true">
      {Array.from({ length: 8 }, (_, i) => (
        <div key={i} className="euvd-fila euvd-esqueleto">
          {[62, 92, 55, 48, 70, 45, 60].map((ancho, j) => (
            <span key={j}>
              <span className="euvd-hueso" style={{ width: `${ancho}%` }} />
            </span>
          ))}
        </div>
      ))}
    </div>
  );
}

const SOL = (
  <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">
    <circle cx="12" cy="12" r="4.2" fill="currentColor" />
    <g stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M12 2.6v2.2M12 19.2v2.2M2.6 12h2.2M19.2 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6" />
    </g>
  </svg>
);

const LUNA = (
  <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" focusable="false">
    <path d="M20.5 14.6A8.6 8.6 0 0 1 9.4 3.5a8.6 8.6 0 1 0 11.1 11.1z" fill="currentColor" />
  </svg>
);

/* --------------------------------------------------------------------------
 * Componente
 * -------------------------------------------------------------------------- */

export default function FeedVulnerabilidades() {
  const inicial = useMemo(leerUrl, []);

  const [datos, setDatos] = useState(null);
  const [cargando, setCargando] = useState(true);
  const [busqueda, setBusqueda] = useState(inicial.busqueda);
  const [filtros, setFiltros] = useState(inicial.filtros);
  const [soloKev, setSoloKev] = useState(inicial.soloKev);
  const [topAbierto, setTopAbierto] = useState(true);
  const [orden, setOrden] = useState(inicial.orden);
  const [pagina, setPagina] = useState(inicial.pagina);
  const [abierta, setAbierta] = useState(inicial.abierta);
  const [tema, setTema] = useState(temaInicial);

  const buscadorRef = useRef(null);
  const tablaRef = useRef(null);
  const montado = useRef(false);

  // Teclear filtra al momento sobre cientos de filas; diferirlo deja que el
  // cursor del buscador siga fluido mientras React recompone la tabla.
  const busquedaDiferida = useDeferredValue(busqueda);
  const filtrando = busqueda !== busquedaDiferida;

  useEffect(() => {
    let vigente = true;
    fetch(`${RUTA_DATOS}?t=${Date.now()}`, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error(String(r.status));
        return r.json();
      })
      .then((json) => {
        if (vigente) setDatos(json);
      })
      .catch(() => {
        if (vigente) setDatos(EJEMPLO);
      })
      .finally(() => {
        if (vigente) setCargando(false);
      });
    return () => {
      vigente = false;
    };
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(CLAVE_TEMA, tema);
    } catch {
      // Sin persistencia el tema dura la sesión; no es motivo para romper nada.
    }
    // El contenedor no cubre el viewport si la lista es corta, y el body de
    // index.html trae el fondo oscuro fijo: sin esto el tema claro deja una
    // banda negra debajo.
    document.body.style.background = FONDO[tema];
    document.documentElement.style.colorScheme = tema;
  }, [tema]);

  const items = datos?.items ?? [];

  const conteos = useMemo(() => {
    const acc = {};
    for (const clave of ORDEN_SEVERIDAD) acc[clave] = 0;
    for (const v of items) acc[v.severidad ?? "sin_puntuar"]++;
    return acc;
  }, [items]);

  const enKev = useMemo(() => items.filter((v) => v.kev).length, [items]);

  // Las que están por explotadas y no por recientes: el sync las trae del catálogo
  // de KEV aunque su publicación quede fuera de la ventana. Se cuentan aparte
  // porque el recuento de arriba dice "en los últimos N días" y estas no lo están.
  const fueraDeVentana = useMemo(() => items.filter((v) => v.fueraDeVentana).length, [items]);
  const enVentana = items.length - fueraDeVentana;

  const top = useMemo(() => [...items].sort(porPrioridad).slice(0, TOP_N), [items]);

  const filtradas = useMemo(() => {
    const q = busquedaDiferida.trim().toLowerCase();
    let salida = items;

    if (filtros.length) {
      salida = salida.filter((v) => filtros.includes(v.severidad ?? "sin_puntuar"));
    }

    if (soloKev) salida = salida.filter((v) => v.kev);

    if (q) {
      salida = salida.filter((v) =>
        [v.cve, v.euvd, v.vendor, v.producto, v.nombre, ...(v.cwes ?? []).map(textoCwe)]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(q)
      );
    }

    const columna = COLUMNAS.find((c) => c.clave === orden.campo) ?? COLUMNAS.at(-1);
    return [...salida].sort(comparador(columna, orden.dir));
  }, [items, busquedaDiferida, filtros, soloKev, orden]);

  // Cambiar de criterio manda a la página 1, pero no en el primer render: ahí
  // machacaría la página que venía en la URL de un enlace compartido.
  useEffect(() => {
    if (montado.current) setPagina(0);
    else montado.current = true;
  }, [busquedaDiferida, filtros, soloKev, orden]);

  const paginas = Math.max(1, Math.ceil(filtradas.length / POR_PAGINA));

  useEffect(() => {
    if (pagina > paginas - 1) setPagina(paginas - 1);
  }, [pagina, paginas]);

  const visibles = filtradas.slice(pagina * POR_PAGINA, (pagina + 1) * POR_PAGINA);

  useEffect(() => {
    escribirUrl({ busqueda: busquedaDiferida, filtros, soloKev, orden, pagina, abierta });
  }, [busquedaDiferida, filtros, soloKev, orden, pagina, abierta]);

  // La barra "/" y Ctrl/Cmd+K llevan al buscador; Escape lo vacía o cierra el detalle.
  useEffect(() => {
    const alPulsar = (e) => {
      const enCampo =
        /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;

      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !enCampo)) {
        e.preventDefault();
        buscadorRef.current?.focus();
        buscadorRef.current?.select();
        return;
      }

      if (e.key === "Escape") {
        if (document.activeElement === buscadorRef.current && busqueda) setBusqueda("");
        else setAbierta(null);
      }
    };

    window.addEventListener("keydown", alPulsar);
    return () => window.removeEventListener("keydown", alPulsar);
  }, [busqueda]);

  const irAPagina = useCallback((n) => {
    setPagina(n);
    // Cambiar de página con el scroll abajo deja la nueva empezada por la mitad:
    // hay que volver al principio de la tabla, no al de la página.
    tablaRef.current?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, []);

  const irAFila = (v) => {
    setBusqueda(v.cve ?? v.euvd);
    setFiltros([]);
    setSoloKev(false);
    setAbierta(v.euvd);
  };

  const ordenarPor = (columna) =>
    setOrden((prev) =>
      prev.campo === columna.clave
        ? { campo: prev.campo, dir: prev.dir === "asc" ? "desc" : "asc" }
        : { campo: columna.clave, dir: columna.porDefecto }
    );

  const alternarFiltro = (clave) =>
    setFiltros((prev) =>
      prev.includes(clave) ? prev.filter((c) => c !== clave) : [...prev, clave]
    );

  const limpiar = () => {
    setBusqueda("");
    setFiltros([]);
    setSoloKev(false);
  };

  const hayFiltros = busqueda.trim() !== "" || filtros.length > 0 || soloKev;

  /** Flechas e Inicio/Fin mueven el foco entre filas sin tabular celda a celda. */
  const navegarFilas = (e) => {
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) return;

    const filas = [...(tablaRef.current?.querySelectorAll(".euvd-dato") ?? [])];
    const i = filas.indexOf(e.currentTarget);
    if (i < 0) return;

    const destino =
      e.key === "ArrowDown"
        ? filas[i + 1]
        : e.key === "ArrowUp"
        ? filas[i - 1]
        : e.key === "Home"
        ? filas[0]
        : filas.at(-1);

    if (destino) {
      e.preventDefault();
      destino.focus();
    }
  };

  const sincronizado = formatearHora(datos?.generado);
  const frescura = hace(datos?.generado);

  return (
    <div className="euvd" data-tema={tema}>
      <style>{CSS}</style>

      <div className="euvd-marco">
        <header className="euvd-cabecera">
          <div className="euvd-titulo">
            <h1>Recently published vulnerabilities</h1>
            <p className="euvd-fuente">
              EU Vulnerability Database (ENISA) · CVSS from the EUVD · titles and CWEs
              from cve.org · EPSS by FIRST · known exploitation from CISA/EU KEV
            </p>
            {frescura && (
              <span className="euvd-sync" title={`Last sync: ${sincronizado}`}>
                <span className="euvd-latido" aria-hidden="true" />
                Synced {frescura}
              </span>
            )}
          </div>

          <div className="euvd-cabecera-lado">
            <button
              type="button"
              className="euvd-tema"
              onClick={() => setTema((t) => (t === "dark" ? "light" : "dark"))}
              title={tema === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              aria-label={tema === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            >
              {tema === "dark" ? SOL : LUNA}
            </button>

            <div className="euvd-recuento">
              <span className="euvd-cifra">{items.length}</span>
              <span className="euvd-cifra-pie">
                {enVentana} in the last {datos?.ventanaDias ?? 14} days
                {fueraDeVentana > 0 && <> {"+ "}{fueraDeVentana} older</>}
                {enKev > 0 && (
                  <>
                    {" · "}
                    <b style={{ color: KEV_COLOR }}>{enKev} exploited</b>
                  </>
                )}
              </span>
            </div>
          </div>
        </header>

        {/* Con un corte puesto el feed arranca vacío y se va llenando, así que se
            dice desde cuándo: si no, unas pocas filas en una ventana de 14 días
            parecen una descarga rota en vez de un feed recién empezado. */}
        {datos?.corte && (
          <div className="euvd-aviso">
            Collecting from scratch since <b>{String(datos.corte).slice(0, 10)}</b>: only
            vulnerabilities published after that show up here, and they drop off after{" "}
            {datos?.ventanaDias ?? 14} days.
          </div>
        )}

        {/* `totalEnEuvd` es lo que la EUVD dice tener en la ventana, así que se
            compara con lo que vino de la ventana: sumarle lo sembrado por KEV
            taparía el aviso justo cuando la paginación se estuviera quedando corta.
            Con un corte puesto la comparación no dice nada —sobran a propósito casi
            todas—, así que el aviso se calla en vez de gritar cada pasada. */}
        {!datos?.corte && datos?.totalEnEuvd > enVentana && (
          <div className="euvd-aviso">
            The EUVD lists <b>{datos.totalEnEuvd}</b> vulnerabilities in this window but the
            JSON only holds <b>{enVentana}</b>. Raise <code>MAX_PAGINAS</code> in the sync:
            what is missing is not the oldest ones, it is whatever the API did not return.
          </div>
        )}

        {datos?.demo && (
          <div className="euvd-aviso">
            Sample data. Could not read <code>{RUTA_DATOS}</code>: run{" "}
            <code>euvd_sync.php</code> to generate it.
          </div>
        )}

        {/* La barra no es solo un gráfico: cada tramo filtra por su severidad, que
            es justo lo que se quiere hacer después de mirarla. */}
        {items.length > 0 && (
          <div className="euvd-distribucion" role="group" aria-label="Breakdown by severity">
            {ORDEN_SEVERIDAD.filter((c) => conteos[c] > 0).map((clave) => {
              const activo = filtros.includes(clave);
              const pct = Math.round((conteos[clave] / items.length) * 100);
              return (
                <button
                  key={clave}
                  type="button"
                  className={activo ? "euvd-tramo es-activo" : "euvd-tramo"}
                  style={{ flexGrow: conteos[clave] }}
                  aria-pressed={activo}
                  onClick={() => alternarFiltro(clave)}
                  title={`${SEVERIDADES[clave].etiqueta}: ${conteos[clave]} (${pct}%) · click to filter`}
                >
                  <span
                    className="euvd-tramo-color"
                    style={{ background: SEVERIDADES[clave].color }}
                  />
                </button>
              );
            })}
          </div>
        )}

        {top.length > 0 && (
          <section className="euvd-top">
            <div className="euvd-top-cabecera">
              <h2>
                Top {top.length}
                <span className="euvd-top-pie">
                  by priority · known exploitation first, then probability × impact
                </span>
              </h2>
              <button
                type="button"
                className="euvd-top-plegar"
                onClick={() => setTopAbierto((v) => !v)}
                aria-expanded={topAbierto}
              >
                {topAbierto ? "Hide" : "Show"}
              </button>
            </div>

            {topAbierto && (
              <ol className="euvd-top-lista">
                {top.map((v, i) => {
                  const sev = SEVERIDADES[v.severidad ?? "sin_puntuar"];
                  const epss = v.epss != null ? tramoEpss(v.epss) : null;
                  return (
                    <li key={v.euvd}>
                      <button
                        type="button"
                        className="euvd-top-ficha"
                        onClick={() => irAFila(v)}
                        title="Show this vulnerability in the table"
                        style={{ borderLeftColor: v.kev ? KEV_COLOR : sev.color }}
                      >
                        <span className="euvd-top-fila1">
                          <b className="euvd-top-puesto">{i + 1}</b>
                          <span className="euvd-top-cve">{v.cve ?? v.euvd}</span>
                          {v.kev && <span className="euvd-kev">Exploited</span>}
                        </span>

                        <span className="euvd-top-nombre">{v.nombre}</span>

                        {(v.vendor || v.producto) && (
                          <span className="euvd-top-quien">
                            {[v.vendor, v.producto].filter(Boolean).join(" · ")}
                          </span>
                        )}

                        <span className="euvd-top-cifras">
                          <span style={{ color: sev.color }}>
                            CVSS {v.score > 0 ? v.score.toFixed(1) : "—"}
                          </span>
                          <span style={{ color: epss ? epss.color : undefined }}>
                            EPSS {epss ? formatearEpss(v.epss) : "no data"}
                          </span>
                          <time dateTime={v.fecha ?? undefined}>{formatearFecha(v.fecha)}</time>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>
        )}

        <div className="euvd-controles">
          <div className="euvd-buscador-caja">
            <svg
              className="euvd-lupa"
              viewBox="0 0 24 24"
              width="16"
              height="16"
              aria-hidden="true"
              focusable="false"
            >
              <circle cx="10.5" cy="10.5" r="6.5" fill="none" stroke="currentColor" strokeWidth="1.9" />
              <path d="M15.4 15.4 21 21" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" />
            </svg>

            <input
              ref={buscadorRef}
              className="euvd-buscador"
              type="search"
              value={busqueda}
              onChange={(e) => setBusqueda(e.target.value)}
              placeholder="Search by CVE, vendor, product, CWE or description"
              aria-label="Search vulnerabilities"
            />

            {busqueda ? (
              <button
                type="button"
                className="euvd-borrar"
                aria-label="Clear search"
                onClick={() => {
                  setBusqueda("");
                  buscadorRef.current?.focus();
                }}
              >
                ×
              </button>
            ) : (
              <kbd className="euvd-atajo" aria-hidden="true">
                /
              </kbd>
            )}
          </div>

          <div className="euvd-chips">
            {ORDEN_SEVERIDAD.map((clave) => {
              const activo = filtros.includes(clave);
              return (
                <button
                  key={clave}
                  type="button"
                  onClick={() => alternarFiltro(clave)}
                  aria-pressed={activo}
                  className={`euvd-chip${activo ? " es-activo" : ""}`}
                  style={activo ? { borderColor: SEVERIDADES[clave].color } : undefined}
                >
                  <span
                    className="euvd-punto"
                    style={{ background: SEVERIDADES[clave].color }}
                  />
                  {SEVERIDADES[clave].etiqueta}
                  <span className="euvd-chip-num">{conteos[clave] ?? 0}</span>
                </button>
              );
            })}

            {enKev > 0 && (
              <button
                type="button"
                onClick={() => setSoloKev((v) => !v)}
                aria-pressed={soloKev}
                className={`euvd-chip euvd-chip-kev${soloKev ? " es-activo" : ""}`}
                style={soloKev ? { borderColor: KEV_COLOR } : undefined}
                title="Only the ones listed as exploited in CISA KEV or EU KEV"
              >
                <span className="euvd-punto" style={{ background: KEV_COLOR }} />
                Exploited
                <span className="euvd-chip-num">{enKev}</span>
              </button>
            )}
          </div>

          {/* Debajo de 980px la cabecera de la tabla no se pinta, así que este
              desplegable es la única forma de ordenar; en escritorio sobra. */}
          <select
            className="euvd-orden"
            value={`${orden.campo}_${orden.dir}`}
            onChange={(e) => {
              const [campo, dir] = e.target.value.split("_");
              setOrden({ campo, dir });
            }}
            aria-label="Sort results"
          >
            {COLUMNAS.map((col) => {
              const dirs = col.porDefecto === "asc" ? ["asc", "desc"] : ["desc", "asc"];
              return dirs.map((dir) => (
                <option key={`${col.clave}_${dir}`} value={`${col.clave}_${dir}`}>
                  {col.orden[dir]}
                </option>
              ));
            })}
          </select>
        </div>

        <div className="euvd-resumen">
          <span role="status" aria-live="polite">
            {cargando
              ? "Loading the feed…"
              : hayFiltros
              ? `${filtradas.length} of ${items.length} vulnerabilities`
              : `${filtradas.length} vulnerabilities`}
          </span>
          {hayFiltros && (
            <button type="button" className="euvd-reset" onClick={limpiar}>
              Clear filters
            </button>
          )}
        </div>

        {cargando ? (
          <Esqueleto />
        ) : filtradas.length === 0 ? (
          <div className="euvd-estado">
            <p>No results for those criteria.</p>
            <button type="button" className="euvd-boton" onClick={limpiar}>
              Clear search and filters
            </button>
          </div>
        ) : (
          <div
            ref={tablaRef}
            className={`euvd-tabla${filtrando ? " es-filtrando" : ""}`}
            role="table"
          >
            <div className="euvd-fila euvd-encabezado" role="row">
              {COLUMNAS.map((col) => {
                const activa = orden.campo === col.clave;
                return (
                  <span
                    key={col.clave}
                    role="columnheader"
                    aria-sort={activa ? (orden.dir === "asc" ? "ascending" : "descending") : "none"}
                    className={activa ? "es-activo" : undefined}
                  >
                    <button
                      type="button"
                      className="euvd-orden-col"
                      onClick={() => ordenarPor(col)}
                      title={col.titulo ?? `Sort by ${col.etiqueta.toLowerCase()}`}
                    >
                      {col.etiqueta}
                      <span className="euvd-flecha" aria-hidden="true">
                        {activa ? (orden.dir === "asc" ? "▲" : "▼") : ""}
                      </span>
                    </button>
                  </span>
                );
              })}
            </div>

            {visibles.map((v) => {
              const sev = SEVERIDADES[v.severidad ?? "sin_puntuar"];
              const cwes = v.cwes ?? [];
              const epss = v.epss != null ? tramoEpss(v.epss) : null;
              const expandida = abierta === v.euvd;
              return (
                <div key={v.euvd} className="euvd-grupo">
                  <div
                    className={`euvd-fila euvd-dato${expandida ? " es-abierta" : ""}`}
                    role="row"
                    tabIndex={0}
                    aria-expanded={expandida}
                    onClick={() => setAbierta(expandida ? null : v.euvd)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setAbierta(expandida ? null : v.euvd);
                        return;
                      }
                      navegarFilas(e);
                    }}
                    style={{ borderLeftColor: v.kev ? KEV_COLOR : sev.color }}
                  >
                    <span className="euvd-id" role="cell">
                      <span className="euvd-etiqueta-movil">CVE</span>
                      <span className="euvd-id-caja">
                        {v.cve ? (
                          v.enlace ? (
                            <a
                              href={v.enlace}
                              target="_blank"
                              rel="noreferrer noopener"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {v.cve}
                            </a>
                          ) : (
                            v.cve
                          )
                        ) : (
                          <span className="euvd-nulo">{v.euvd}</span>
                        )}
                        {v.kev && (
                          <span
                            className="euvd-kev"
                            title={`Known exploitation · ${v.kev.fuentes.map(nombreFuenteKev).join(" and ") || "KEV"}${
                              v.kev.fecha ? ` · listed on ${formatearFecha(v.kev.fecha)}` : ""
                            }`}
                          >
                            Exploited
                          </span>
                        )}
                      </span>
                    </span>

                    <span className="euvd-nombre" role="cell">
                      {v.nombre}
                      {v.producto && <em className="euvd-producto">{v.producto}</em>}
                    </span>

                    <span className="euvd-vendor" role="cell">
                      <span className="euvd-etiqueta-movil">Vendor</span>
                      {v.vendor ?? <span className="euvd-nulo">Unassigned</span>}
                    </span>

                    <span className="euvd-cwe" role="cell">
                      <span className="euvd-etiqueta-movil">CWE</span>
                      {cwes.length === 0 ? (
                        <span className="euvd-nulo">No CWE</span>
                      ) : (
                        <span className="euvd-cwe-caja">
                          {cwes.slice(0, CWE_VISIBLES).map((cwe) => (
                            <a
                              key={cwe.id}
                              className="euvd-cwe-id"
                              href={enlaceCwe(cwe.id)}
                              target="_blank"
                              rel="noreferrer noopener"
                              title={textoCwe(cwe)}
                              onClick={(e) => e.stopPropagation()}
                            >
                              {cwe.id}
                            </a>
                          ))}
                          {cwes.length > CWE_VISIBLES && (
                            <span
                              className="euvd-cwe-mas"
                              title={cwes.slice(CWE_VISIBLES).map(textoCwe).join(" · ")}
                            >
                              +{cwes.length - CWE_VISIBLES}
                            </span>
                          )}
                        </span>
                      )}
                    </span>

                    <span className="euvd-severidad" role="cell">
                      <span className="euvd-etiqueta-movil">Severity</span>
                      <span className="euvd-medida">
                        <span className="euvd-pista">
                          <span
                            className="euvd-relleno"
                            style={{
                              width: `${((v.score ?? 0) / 10) * 100}%`,
                              background: sev.color,
                            }}
                          />
                        </span>
                        <b
                          style={{ color: sev.color }}
                          title={
                            v.score > 0
                              ? "CVSS from the EUVD"
                              : "The EUVD has not scored this CVE yet"
                          }
                        >
                          {v.score > 0 ? v.score.toFixed(1) : "—"}
                        </b>
                      </span>
                      <span className="euvd-sev-texto">{sev.etiqueta}</span>
                    </span>

                    <span className="euvd-epss" role="cell">
                      <span className="euvd-etiqueta-movil">EPSS</span>
                      {epss ? (
                        <span className="euvd-epss-caja" title={descripcionEpss(v)}>
                          <b style={{ color: epss.color }}>
                            {formatearEpss(v.epss)}
                            {v.origenEpss === "euvd" && <span className="euvd-origen">EUVD</span>}
                          </b>
                          {v.epssPercentil != null && (
                            <span className="euvd-epss-pie">
                              {(v.epssPercentil * 100).toFixed(0)}th pct
                            </span>
                          )}
                        </span>
                      ) : (
                        <span
                          className="euvd-nulo euvd-epss-vacio"
                          title="The FIRST model is published daily and does not score this CVE yet: it takes a few days after publication"
                        >
                          No data
                        </span>
                      )}
                    </span>

                    <span className="euvd-fecha" role="cell">
                      <span className="euvd-etiqueta-movil">Date</span>
                      <time dateTime={v.fecha ?? undefined}>{formatearFecha(v.fecha)}</time>
                      <span className="euvd-chevron" aria-hidden="true">
                        ›
                      </span>
                    </span>
                  </div>

                  {expandida && (
                    <div className="euvd-detalle">
                      <p>{v.descripcion || v.nombre}</p>
                      <dl>
                        <div>
                          <dt>EUVD</dt>
                          <dd>{v.euvd}</dd>
                        </div>
                        {v.cvss && (
                          <div>
                            <dt>CVSS</dt>
                            <dd>v{v.cvss}</dd>
                          </div>
                        )}
                        {epss && (
                          <div>
                            <dt>EPSS</dt>
                            <dd style={{ color: epss.color }}>
                              {formatearEpss(v.epss)}
                              {v.epssPercentil != null &&
                                ` · ${(v.epssPercentil * 100).toFixed(1)}th percentile`}
                            </dd>
                          </div>
                        )}
                        {epss && (
                          <div>
                            <dt>Exploitation</dt>
                            <dd className="euvd-detalle-texto">
                              {epss.etiqueta}
                              {v.epssFecha ? ` · ${formatearFecha(v.epssFecha)}` : ""}
                              {v.origenEpss === "euvd" ? " · EUVD figure" : " · FIRST"}
                            </dd>
                          </div>
                        )}
                        {v.kev && (
                          <div>
                            <dt>Known exploitation</dt>
                            <dd className="euvd-detalle-texto" style={{ color: KEV_COLOR }}>
                              {v.kev.fuentes.map(nombreFuenteKev).join(" and ") || "KEV"}
                              {v.kev.fecha && ` · listed on ${formatearFecha(v.kev.fecha)}`}
                            </dd>
                          </div>
                        )}
                        {v.assigner && (
                          <div>
                            <dt>CNA</dt>
                            <dd>{v.assigner}</dd>
                          </div>
                        )}
                      </dl>

                      {cwes.length > 0 && (
                        <div className="euvd-cwe-lista">
                          <span className="euvd-cwe-titulo">Weaknesses (CWE)</span>
                          <ul>
                            {cwes.map((cwe) => (
                              <li key={cwe.id}>
                                <a
                                  href={enlaceCwe(cwe.id)}
                                  target="_blank"
                                  rel="noreferrer noopener"
                                >
                                  {cwe.id}
                                </a>
                                {cwe.nombre && <span>{cwe.nombre}</span>}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {v.vector && (
                        <div className="euvd-vector-caja">
                          <code className="euvd-vector">{v.vector}</code>
                          <BotonCopiar texto={v.vector} titulo="Copy the CVSS vector" />
                        </div>
                      )}

                      <div className="euvd-acciones">
                        {v.cve && <BotonCopiar texto={v.cve} etiqueta={`Copy ${v.cve}`} />}
                        {v.enlace && (
                          <a
                            className="euvd-accion"
                            href={v.enlace}
                            target="_blank"
                            rel="noreferrer noopener"
                            onClick={(e) => e.stopPropagation()}
                          >
                            NVD ↗
                          </a>
                        )}
                        <a
                          className="euvd-accion"
                          href={`https://euvd.enisa.europa.eu/vulnerability/${v.euvd}`}
                          target="_blank"
                          rel="noreferrer noopener"
                          onClick={(e) => e.stopPropagation()}
                        >
                          EUVD ↗
                        </a>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {paginas > 1 && (
          <nav className="euvd-paginacion" aria-label="Pagination">
            <button
              type="button"
              className="euvd-pag-boton"
              onClick={() => irAPagina(Math.max(0, pagina - 1))}
              disabled={pagina === 0}
            >
              ‹ Previous
            </button>

            <span className="euvd-pag-numeros">
              {paginasVisibles(pagina, paginas).map((n, i) =>
                n === "hueco" ? (
                  <span key={`h${i}`} className="euvd-pag-salto" aria-hidden="true">
                    …
                  </span>
                ) : (
                  <button
                    key={n}
                    type="button"
                    className={`euvd-pag-num${n === pagina ? " es-activo" : ""}`}
                    aria-current={n === pagina ? "page" : undefined}
                    aria-label={`Page ${n + 1}`}
                    onClick={() => irAPagina(n)}
                  >
                    {n + 1}
                  </button>
                )
              )}
            </span>

            <button
              type="button"
              className="euvd-pag-boton"
              onClick={() => irAPagina(Math.min(paginas - 1, pagina + 1))}
              disabled={pagina >= paginas - 1}
            >
              Next ›
            </button>
          </nav>
        )}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------------------
 * Estilos
 *
 * Dos temas sobre el mismo juego de variables. Los colores de severidad también
 * son variables y no literales: el amarillo y el naranja que se leen sobre el
 * fondo oscuro se vuelven ilegibles sobre blanco, así que el tema claro los
 * sustituye por versiones más oscuras en vez de renunciar al código de color.
 * -------------------------------------------------------------------------- */

const CSS = `
.euvd {
  --bg: #0e1116;
  --superficie: #161a22;
  --superficie-2: #1d2330;
  --hundido: #0b0e13;
  --linea: #232936;
  --linea-fuerte: #2e3648;
  --texto: #e4e8f0;
  --texto-2: #c3cad8;
  --apagado: #8b93a6;
  --acento: #8ea4ff;
  --anillo: rgba(142, 164, 255, 0.28);
  --sombra: 0 1px 2px rgba(0, 0, 0, 0.35);

  --sev-critica: #ff6b6b;
  --sev-alta: #ff9f45;
  --sev-media: #e8cc57;
  --sev-baja: #63b3ed;
  --sev-nula: #7d8598;

  --kev: #ff4d4d;
  --kev-borde: rgba(255, 77, 77, 0.45);
  --kev-fondo: rgba(255, 77, 77, 0.12);

  --aviso-borde: #4a3b1c;
  --aviso-fondo: rgba(232, 204, 87, 0.08);
  --aviso-texto: #e8cc57;

  --mono: ui-monospace, "JetBrains Mono", SFMono-Regular, Menlo, Consolas, monospace;

  background: var(--bg);
  color: var(--texto);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 15px;
  line-height: 1.5;
  padding: 28px 20px 56px;
  min-height: 100%;
  box-sizing: border-box;
  -webkit-font-smoothing: antialiased;
}

.euvd[data-tema="light"] {
  --bg: #f5f6f9;
  --superficie: #ffffff;
  --superficie-2: #eef1f6;
  --hundido: #f7f8fb;
  --linea: #e1e5ee;
  --linea-fuerte: #ccd3e0;
  --texto: #151922;
  --texto-2: #3d4553;
  --apagado: #5f6878;
  --acento: #3352d8;
  --anillo: rgba(51, 82, 216, 0.2);
  --sombra: 0 1px 2px rgba(16, 24, 40, 0.06);

  --sev-critica: #c92a37;
  --sev-alta: #a3540b;
  --sev-media: #7b6200;
  --sev-baja: #1f5fbd;
  --sev-nula: #6b7280;

  --kev: #c92a37;
  --kev-borde: rgba(201, 42, 55, 0.35);
  --kev-fondo: rgba(201, 42, 55, 0.08);

  --aviso-borde: #e6d29a;
  --aviso-fondo: #fdf7e6;
  --aviso-texto: #74581a;
}

.euvd *, .euvd *::before, .euvd *::after { box-sizing: border-box; }

/* En un monitor ancho la tabla se estira hasta romper la relación entre el
   nombre y sus cifras, que acaban a medio metro de distancia. */
.euvd-marco { max-width: 1560px; margin: 0 auto; }

/* Cabecera --------------------------------------------------------------- */

.euvd-cabecera {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 20px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}
.euvd-titulo { min-width: 0; }
.euvd-cabecera h1 {
  font-size: 26px;
  font-weight: 650;
  letter-spacing: -0.021em;
  margin: 0 0 5px;
}
.euvd-fuente { color: var(--apagado); font-size: 13px; margin: 0; }

.euvd-sync {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
  padding: 3px 9px 3px 7px;
  border: 1px solid var(--linea);
  border-radius: 999px;
  background: var(--superficie);
  color: var(--apagado);
  font-size: 11.5px;
  cursor: help;
}
.euvd-latido {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #35c07a;
  box-shadow: 0 0 0 0 rgba(53, 192, 122, 0.5);
  animation: euvd-latir 2.4s ease-out infinite;
}
@keyframes euvd-latir {
  0% { box-shadow: 0 0 0 0 rgba(53, 192, 122, 0.5); }
  70% { box-shadow: 0 0 0 6px rgba(53, 192, 122, 0); }
  100% { box-shadow: 0 0 0 0 rgba(53, 192, 122, 0); }
}

.euvd-cabecera-lado { display: flex; align-items: center; gap: 14px; }
.euvd-tema {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 34px;
  height: 34px;
  flex: none;
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 8px;
  color: var(--apagado);
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s, background 0.15s;
}
.euvd-tema:hover { color: var(--texto); border-color: var(--linea-fuerte); }

.euvd-recuento { text-align: right; line-height: 1.15; }
.euvd-cifra {
  display: block;
  font-family: var(--mono);
  font-size: 30px;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
}
.euvd-cifra-pie { color: var(--apagado); font-size: 12px; }

.euvd-aviso {
  border: 1px solid var(--aviso-borde);
  background: var(--aviso-fondo);
  color: var(--aviso-texto);
  border-radius: 8px;
  padding: 10px 14px;
  font-size: 13px;
  margin-bottom: 16px;
}
.euvd-aviso code { font-family: var(--mono); font-size: 12px; }

/* Distribución por severidad --------------------------------------------- */

.euvd-distribucion { display: flex; gap: 3px; margin-bottom: 20px; }
.euvd-tramo {
  display: flex;
  align-items: center;
  flex: 1 1 0;
  min-width: 6px;
  background: none;
  border: 0;
  border-radius: 4px;
  padding: 8px 0;
  cursor: pointer;
}
.euvd-tramo-color {
  display: block;
  width: 100%;
  height: 6px;
  border-radius: 3px;
  opacity: 0.82;
  transition: opacity 0.15s ease, height 0.15s ease;
}
.euvd-tramo:hover .euvd-tramo-color,
.euvd-tramo.es-activo .euvd-tramo-color { opacity: 1; height: 11px; }

/* Top ------------------------------------------------------------------- */

.euvd-top { margin-bottom: 24px; }
.euvd-top-cabecera {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.euvd-top-cabecera h2 {
  display: flex;
  align-items: baseline;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 15px;
  font-weight: 650;
  margin: 0;
}
.euvd-top-pie { color: var(--apagado); font-size: 12px; font-weight: 400; }
.euvd-top-plegar {
  background: none;
  border: 0;
  color: var(--acento);
  font: inherit;
  font-size: 13px;
  padding: 0;
  cursor: pointer;
  flex: none;
}
.euvd-top-plegar:hover { text-decoration: underline; }

.euvd-top-lista {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(330px, 1fr));
  gap: 10px;
  list-style: none;
  margin: 0;
  padding: 0;
}
.euvd-top-ficha {
  display: flex;
  flex-direction: column;
  gap: 4px;
  width: 100%;
  height: 100%;
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-left: 3px solid transparent;
  border-radius: 8px;
  padding: 11px 13px;
  color: var(--texto);
  font: inherit;
  text-align: left;
  cursor: pointer;
  box-shadow: var(--sombra);
  transition: background 0.15s ease, border-color 0.15s ease, transform 0.15s ease;
}
.euvd-top-ficha:hover {
  background: var(--superficie-2);
  border-color: var(--linea-fuerte);
  transform: translateY(-1px);
}

.euvd-top-fila1 { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.euvd-top-puesto {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--apagado);
  min-width: 16px;
}
.euvd-top-cve { font-family: var(--mono); font-size: 13px; color: var(--acento); }
.euvd-top-nombre {
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
  font-size: 13px;
  line-height: 1.35;
}
.euvd-top-quien {
  color: var(--apagado);
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.euvd-top-cifras {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 2px;
  font-family: var(--mono);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}
.euvd-top-cifras time { color: var(--apagado); margin-left: auto; }

/* Controles -------------------------------------------------------------- */

.euvd-controles {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
  margin-bottom: 12px;
}
.euvd-buscador-caja {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1 1 320px;
  min-width: 0;
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 8px;
  padding: 0 10px;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
.euvd-buscador-caja:focus-within {
  border-color: var(--acento);
  box-shadow: 0 0 0 3px var(--anillo);
}
.euvd-lupa { color: var(--apagado); flex: none; }
.euvd-buscador {
  flex: 1;
  min-width: 0;
  background: none;
  border: 0;
  outline: none;
  color: var(--texto);
  padding: 10px 0;
  font: inherit;
  font-size: 14px;
}
.euvd-buscador::placeholder { color: var(--apagado); }
.euvd-buscador::-webkit-search-cancel-button { -webkit-appearance: none; appearance: none; }

.euvd-atajo {
  flex: none;
  border: 1px solid var(--linea-fuerte);
  border-radius: 4px;
  padding: 1px 6px;
  color: var(--apagado);
  font-family: var(--mono);
  font-size: 11px;
  line-height: 1.5;
}
.euvd-borrar {
  flex: none;
  width: 20px;
  height: 20px;
  border: 0;
  border-radius: 50%;
  background: var(--superficie-2);
  color: var(--apagado);
  font-size: 15px;
  line-height: 1;
  cursor: pointer;
}
.euvd-borrar:hover { color: var(--texto); }

.euvd-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.euvd-chip {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 999px;
  color: var(--apagado);
  padding: 7px 12px;
  font: inherit;
  font-size: 13px;
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}
.euvd-chip:hover { color: var(--texto); border-color: var(--linea-fuerte); }
.euvd-chip.es-activo { color: var(--texto); background: var(--superficie-2); }
.euvd-punto { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.euvd-chip-num { font-family: var(--mono); font-size: 11px; opacity: 0.7; }
.euvd-chip-kev.es-activo { color: var(--texto); background: var(--kev-fondo); }

.euvd-orden {
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 8px;
  color: var(--texto);
  padding: 9px 12px;
  font: inherit;
  font-size: 14px;
}

.euvd-resumen {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 24px;
  margin-bottom: 6px;
  color: var(--apagado);
  font-size: 12.5px;
  font-variant-numeric: tabular-nums;
}
.euvd-reset {
  background: none;
  border: 0;
  padding: 0;
  color: var(--acento);
  font: inherit;
  font-size: 12.5px;
  cursor: pointer;
}
.euvd-reset:hover { text-decoration: underline; }

.euvd-estado {
  color: var(--apagado);
  padding: 48px 0;
  text-align: center;
}
.euvd-estado p { margin: 0 0 14px; }
.euvd-boton {
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 8px;
  color: var(--texto);
  padding: 8px 16px;
  font: inherit;
  font-size: 13px;
  cursor: pointer;
}
.euvd-boton:hover { border-color: var(--linea-fuerte); background: var(--superficie-2); }

/* Tabla ------------------------------------------------------------------ */

.euvd-tabla { border-top: 1px solid var(--linea); }
/* Mientras se recalcula el filtrado la tabla se apaga un poco: dice que está
   trabajando sin mover nada de sitio. */
.euvd-tabla.es-filtrando { opacity: 0.55; transition: opacity 0.12s ease; }

.euvd-fila {
  display: grid;
  grid-template-columns: 148px minmax(0, 1fr) 130px 132px 118px 92px 118px;
  gap: 14px;
  align-items: center;
  padding: 12px 14px;
  border-bottom: 1px solid var(--linea);
  border-left: 3px solid transparent;
}
/* Pegada arriba: en una lista de 25 filas se pierde de vista al segundo scroll
   y con ella el saber por qué columna está ordenado. */
.euvd-encabezado {
  position: sticky;
  top: 0;
  z-index: 2;
  background: var(--bg);
  color: var(--apagado);
  font-size: 12px;
  letter-spacing: 0.02em;
  padding-top: 10px;
  padding-bottom: 10px;
}
.euvd-encabezado .es-activo { color: var(--texto); }
.euvd-orden-col {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  max-width: 100%;
  background: none;
  border: 0;
  border-radius: 4px;
  padding: 0;
  color: inherit;
  font: inherit;
  letter-spacing: inherit;
  text-align: left;
  cursor: pointer;
}
.euvd-orden-col:hover { color: var(--texto); }
/* Ancho fijo: sin él la cabecera baila cada vez que la flecha cambia de columna. */
.euvd-flecha { width: 8px; font-size: 8px; line-height: 1; flex: none; }

.euvd-dato { cursor: pointer; transition: background 0.12s ease; }
.euvd-dato:hover, .euvd-dato.es-abierta { background: var(--superficie); }

.euvd-esqueleto { border-left-color: transparent; }
.euvd-hueso {
  display: block;
  height: 10px;
  border-radius: 4px;
  background: linear-gradient(90deg, var(--linea) 25%, var(--superficie-2) 37%, var(--linea) 63%);
  background-size: 400% 100%;
  animation: euvd-brillo 1.4s ease infinite;
}
@keyframes euvd-brillo {
  0% { background-position: 100% 0; }
  100% { background-position: 0 0; }
}

.euvd-id { font-family: var(--mono); font-size: 13px; }
.euvd-id-caja { display: flex; flex-wrap: wrap; align-items: baseline; gap: 3px 6px; }
.euvd-kev {
  font-family: Inter, system-ui, sans-serif;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.03em;
  color: var(--kev);
  border: 1px solid var(--kev-borde);
  background: var(--kev-fondo);
  border-radius: 3px;
  padding: 1px 5px;
  cursor: help;
  white-space: nowrap;
}
.euvd-id a { color: var(--acento); text-decoration: none; }
.euvd-id a:hover { text-decoration: underline; }
.euvd-nulo { color: var(--apagado); }

.euvd-nombre { min-width: 0; }
.euvd-producto {
  display: block;
  color: var(--apagado);
  font-size: 12px;
  font-style: normal;
  margin-top: 2px;
}
.euvd-vendor { color: var(--texto); font-size: 14px; overflow-wrap: anywhere; }

.euvd-cwe { min-width: 0; font-size: 13px; }
.euvd-cwe-caja {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 3px 6px;
  min-width: 0;
}
.euvd-cwe-id {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--acento);
  text-decoration: none;
  white-space: nowrap;
}
.euvd-cwe-id:hover { text-decoration: underline; }
.euvd-cwe-mas {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--apagado);
  border: 1px solid var(--linea);
  border-radius: 3px;
  padding: 0 4px;
  cursor: help;
}
.euvd-epss-caja { display: block; cursor: help; }
.euvd-epss-vacio { font-size: 12px; cursor: help; }
.euvd-epss b {
  font-family: var(--mono);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.euvd-epss-pie { display: block; color: var(--apagado); font-size: 11px; margin-top: 3px; }

.euvd-medida { display: flex; align-items: center; gap: 8px; }
.euvd-pista {
  flex: 1;
  height: 4px;
  background: var(--linea);
  border-radius: 2px;
  overflow: hidden;
}
.euvd-relleno { display: block; height: 100%; }
.euvd-severidad b {
  font-family: var(--mono);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.euvd-sev-texto { display: block; color: var(--apagado); font-size: 11px; margin-top: 3px; }
.euvd-origen {
  margin-left: 4px;
  color: var(--apagado);
  font-size: 9px;
  font-weight: 500;
  letter-spacing: 0.04em;
  vertical-align: 2px;
}

.euvd-fecha {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  font-family: var(--mono);
  font-size: 13px;
  color: var(--apagado);
  font-variant-numeric: tabular-nums;
}
.euvd-fecha time { white-space: nowrap; }
/* La única pista de que la fila se abre; gira al abrirla para confirmarlo. */
.euvd-chevron {
  flex: none;
  font-size: 15px;
  line-height: 1;
  color: var(--linea-fuerte);
  transition: transform 0.15s ease, color 0.15s ease;
}
.euvd-dato:hover .euvd-chevron { color: var(--apagado); }
.euvd-dato.es-abierta .euvd-chevron { transform: rotate(90deg); color: var(--acento); }

/* Detalle ---------------------------------------------------------------- */

.euvd-detalle {
  padding: 6px 18px 20px 32px;
  border-bottom: 1px solid var(--linea);
  background: var(--superficie);
}
.euvd-detalle p { margin: 0 0 14px; max-width: 110ch; color: var(--texto-2); font-size: 14px; }
.euvd-detalle dl { display: flex; flex-wrap: wrap; gap: 24px; margin: 0 0 14px; }
.euvd-detalle dt { color: var(--apagado); font-size: 11px; margin-bottom: 2px; }
.euvd-detalle dd { margin: 0; font-family: var(--mono); font-size: 13px; }
.euvd-detalle-texto { font-family: inherit !important; color: var(--texto-2); }

.euvd-cwe-lista { margin: 0 0 14px; }
.euvd-cwe-titulo { display: block; color: var(--apagado); font-size: 11px; margin-bottom: 6px; }
.euvd-cwe-lista ul { list-style: none; margin: 0; padding: 0; }
.euvd-cwe-lista li {
  display: flex;
  align-items: baseline;
  gap: 10px;
  font-size: 13px;
  padding: 2px 0;
  max-width: 72ch;
}
.euvd-cwe-lista a {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--acento);
  text-decoration: none;
  white-space: nowrap;
}
.euvd-cwe-lista a:hover { text-decoration: underline; }
.euvd-cwe-lista span { color: var(--texto-2); }

.euvd-vector-caja {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.euvd-vector {
  font-family: var(--mono);
  font-size: 12px;
  color: var(--apagado);
  background: var(--hundido);
  border: 1px solid var(--linea);
  border-radius: 5px;
  padding: 5px 9px;
  overflow-wrap: anywhere;
}

.euvd-acciones { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.euvd-copiar, .euvd-accion {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  background: var(--bg);
  border: 1px solid var(--linea);
  border-radius: 6px;
  padding: 5px 10px;
  color: var(--texto-2);
  font: inherit;
  font-size: 12px;
  text-decoration: none;
  cursor: pointer;
  transition: color 0.15s ease, border-color 0.15s ease;
}
.euvd-copiar:hover, .euvd-accion:hover { color: var(--texto); border-color: var(--linea-fuerte); }
.euvd-copiar.es-hecho { color: #35c07a; border-color: #35c07a; }

/* Paginación ------------------------------------------------------------- */

.euvd-paginacion {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-top: 24px;
  color: var(--apagado);
  font-size: 13px;
}
.euvd-pag-numeros { display: flex; align-items: center; gap: 4px; }
.euvd-pag-boton, .euvd-pag-num {
  background: var(--superficie);
  border: 1px solid var(--linea);
  border-radius: 6px;
  color: var(--texto);
  padding: 7px 12px;
  font: inherit;
  font-size: 13px;
  cursor: pointer;
  transition: background 0.15s ease, border-color 0.15s ease;
}
.euvd-pag-num {
  min-width: 34px;
  padding: 7px 8px;
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  color: var(--apagado);
}
.euvd-pag-boton:hover:not(:disabled), .euvd-pag-num:hover {
  border-color: var(--linea-fuerte);
  background: var(--superficie-2);
  color: var(--texto);
}
.euvd-pag-num.es-activo {
  color: var(--texto);
  border-color: var(--acento);
  background: var(--superficie-2);
}
.euvd-pag-boton:disabled { opacity: 0.4; cursor: default; }
.euvd-pag-salto { color: var(--apagado); padding: 0 2px; }

/* Foco ------------------------------------------------------------------- */

.euvd :focus-visible {
  outline: 2px solid var(--acento);
  outline-offset: 2px;
  border-radius: 4px;
}

.euvd-etiqueta-movil { display: none; }

/* Adaptación ------------------------------------------------------------- */

@media (max-width: 1100px) {
  .euvd-fila { grid-template-columns: 132px minmax(0, 1fr) 112px 104px 104px 84px 110px; gap: 10px; }
}

.euvd-orden { display: none; }

@media (max-width: 980px) {
  .euvd-orden { display: block; flex: 1 1 100%; }

  .euvd { padding: 20px 14px 44px; }
  .euvd-cabecera { align-items: flex-start; }
  .euvd-encabezado { display: none; }
  .euvd-chevron { display: none; }
  /* En un móvil no hay tecla que pulsar, y el hueco lo necesita el marcador. */
  .euvd-atajo { display: none; }

  /* Sin cabecera de columnas cada fila pasa a ser una ficha: recuadro propio,
     etiqueta delante de cada dato y aire suficiente para el dedo. */
  .euvd-tabla { border-top: 0; display: grid; gap: 10px; }
  .euvd-grupo {
    border: 1px solid var(--linea);
    border-radius: 10px;
    overflow: hidden;
    background: var(--superficie);
  }
  .euvd-fila {
    grid-template-columns: 1fr;
    gap: 8px;
    padding: 14px;
    border-bottom: 0;
  }
  .euvd-fila > span { display: flex; align-items: baseline; gap: 10px; }
  /* Con la especificidad de ".euvd-fila > span" hace falta el tipo: si no, el
     nombre se vuelve flex y el producto se planta a su derecha. */
  .euvd-fila > span.euvd-nombre { display: block; font-size: 14px; font-weight: 550; }
  .euvd-etiqueta-movil {
    display: inline-block;
    min-width: 74px;
    color: var(--apagado);
    font-size: 11px;
    font-family: Inter, system-ui, sans-serif;
  }
  .euvd-severidad, .euvd-epss { flex-wrap: wrap; }
  .euvd-medida { flex: 1; min-width: 120px; }
  .euvd-sev-texto { margin-top: 0; }
  .euvd-epss-caja { display: flex; align-items: baseline; gap: 10px; }
  .euvd-epss-pie { margin-top: 0; }
  .euvd-detalle { padding: 0 14px 16px; border-bottom: 0; }
  .euvd-cifra { font-size: 24px; }
  .euvd-esqueleto { border: 0; }
}

@media (max-width: 560px) {
  .euvd-cabecera { flex-direction: column; gap: 12px; }
  .euvd-cabecera-lado { width: 100%; justify-content: space-between; flex-direction: row-reverse; }
  .euvd-recuento { text-align: left; }
  .euvd-top-lista { grid-template-columns: 1fr; }
  .euvd-pag-boton { padding: 7px 10px; }
}

@media (prefers-reduced-motion: reduce) {
  .euvd * { transition: none !important; animation: none !important; }
  .euvd-tramo:hover .euvd-tramo-color { height: 6px; }
}
`;
