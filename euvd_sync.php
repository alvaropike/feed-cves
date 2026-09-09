<?php
/**
 * euvd_sync.php
 *
 * Descarga las vulnerabilidades publicadas recientemente en la EU Vulnerability
 * Database (ENISA) y las deja normalizadas en data/cves.json, que es lo que lee
 * la web. Pensado para ejecutarse por cron cada hora.
 *
 * Dos modos:
 *   euvd_sync.php             pasada completa (~190 s)
 *   euvd_sync.php --rapido    solo EUVD + cve.org + KEV (~40 s)
 *
 * Cron en Hostinger, una cadencia para cada uno (minutos y horas explícitos: la
 * forma con barra lleva la secuencia que cerraría este comentario):
 *   0,15,30,45 * * * *    /usr/bin/php /home/USUARIO/euvd_sync.php --rapido
 *   17 0,6,12,18 * * *    /usr/bin/php /home/USUARIO/euvd_sync.php
 * y a cada línea, >> /home/USUARIO/logs/euvd.log 2>&1
 *
 * Requisitos: PHP 8.0+ con cURL.
 */

declare(strict_types=1);

// ---------------------------------------------------------------- configuración

const API_SEARCH = 'https://euvdservices.enisa.europa.eu/api/search';
const API_CVE    = 'https://cveawg.mitre.org/api/cve/';  // registros oficiales de cve.org
const API_KEV    = 'https://euvdservices.enisa.europa.eu/api/kev/dump';  // CISA KEV + EU KEV
const API_ENISAID = 'https://euvdservices.enisa.europa.eu/api/enisaid';  // ficha suelta, por id

// VulnCheck KEV: el mismo catálogo de explotación activa que el de la EUVD, pero
// más grande (5.200 entradas frente a 1.700, y ninguna de la EUVD falta aquí) y
// por delante: CISA suele confirmar uno o dos días después. Es la fuente que
// decide qué llega a Telegram; ver notificar_telegram(). Sin token el sync corre
// igual: la web sale como siempre, con la marca de CISA y EU KEV, y Telegram
// no manda nada, que es lo correcto: sin catálogo no se sabe qué avisar.
const API_VULNCHECK_KEV = 'https://api.vulncheck.com/v3/index/vulncheck-kev';
// El NVD servido por VulnCheck. El catálogo de KEV trae el nombre, el fabricante,
// el producto y las CWE, pero no la puntuación ni la fecha de publicación, y el
// mensaje de Telegram las lleva. Se pide por CVE y solo de lo que se va a mandar
// (unos pocos por pasada), así que no hace falta ni paginar ni cachear en disco.
const API_VULNCHECK_NVD = 'https://api.vulncheck.com/v3/index/nist-nvd2';
const VULNCHECK_PAGE = 1000;  // el máximo que sirve de una vez
// El tier community corta la paginación en 6 páginas: 6.000 entradas, de sobra
// para las 5.200 de hoy pero no para siempre. pedir_vulncheck_kev() avisa en el
// log en cuanto el catálogo no quepa, porque a partir de ahí el filtro de
// Telegram se dejaría fuera lo que no haya bajado.
const VULNCHECK_MAX_PAGINAS = 6;
const VENTANA_DIAS = 14;      // cuántos días hacia atrás pedir
const PAGE_SIZE    = 100;     // máximo que admite la API
// La ventana de 14 días ronda las 6.000 vulnerabilidades, así que 25 páginas se
// quedaban con la mitad —y no con la mitad más reciente, sino con las que
// devolviera la API—. El tope sigue existiendo por seguridad, pero ahora holgado.
//
// A 60 se volvió a quedar corto el 2026-09-08: la EUVD decía 6.039 y bajaban
// 6.000. Y una descarga corta no es solo una web incompleta: lo que falta hoy
// entra mañana como si acabara de salir, que fue justo lo que llenó la cola de
// Telegram con 900 avisos de vulnerabilidades de hasta dos semanas.
const MAX_PAGINAS  = 100;     // tope de seguridad: 100 * 100 = 10.000 registros
const PAUSA_US     = 400000;  // 0,4 s entre peticiones, para no castigar la API
const TIMEOUT      = 30;
const CONCURRENCIA_TITULOS = 6;    // peticiones simultáneas a cve.org
const TANDA_TITULOS        = 300;  // cada cuántos títulos deja una línea de log

const API_EPSS      = 'https://api.first.org/data/v1/epss';  // probabilidad de explotación (FIRST)
const EPSS_TANDA    = 100;     // máximo de CVE que admite una petición a FIRST
const EPSS_PAUSA_US = 300000;

// Del NVD solo se sacan las CWE. La puntuación se dejó de coger: el NIST
// reanaliza por su cuenta y a veces no encajaba con la ficha de la EUVD —otra
// versión del CVSS, otro alcance—, así que el score tiene una sola fuente.
const API_NVD          = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_PAGE         = 2000;  // máximo que admite la API del NVD
const NVD_MAX_PAGINAS  = 15;    // tope de seguridad: 15 * 2.000 = 30.000 CVE
const NVD_MARGEN_DIAS  = 30;    // se pide más ventana de la necesaria; ver completar_cwes_nvd()

const TG_API          = 'https://api.telegram.org/bot';
const TG_MAX_MENSAJES = 12;       // avisos por sala y pasada; lo que sobre se manda en la siguiente
// Las ediciones son silenciosas, así que pueden esperar: este tope existe solo
// para que una tanda de puestas al día no se coma la pasada entera.
const TG_MAX_EDICIONES = 40;      // ediciones por pasada, sumando todas las salas
// El límite que manda no es el del chat sino el del grupo: unos 20 mensajes por
// minuto. Con las seis salas montadas como temas de un mismo grupo, los 1,2 s de
// antes iban a ~50/min contra ese tope y Telegram devolvía 429. 3,5 s deja el
// ritmo en ~17/min, por debajo del límite.
const TG_PAUSA_US     = 3500000;

// Cuántos días puede llevar una fila en el catálogo de KEV para que su primer
// aviso siga siendo una noticia. La ventana ya filtra por fecha de publicación,
// pero el catálogo mete ~1.300 CVE explotadas de las que casi todas son de hace
// años. Ver es_noticia().
const TG_DIAS_NOTICIA = 7;

// Cuánto se recuerda una fila que ha dejado de aparecer. Antes se olvidaba en
// cuanto faltaba de una pasada, y eso convertía cualquier tropiezo de la API en
// un reaviso masivo: una página de la EUVD que falla o un catálogo de KEV que no
// baja dejan la lista a medias, se borran esos apuntes, y a la pasada siguiente
// vuelven las filas sin nada anotado y se avisan como si fueran nuevas. Una
// ventana entera de margen: el fichero no llega al doble y hacen falta dos
// semanas de fallos seguidos para perder un apunte que aún importa.
const TG_OLVIDO_DIAS  = 14;

// Opcional: exporta NVD_API_KEY en el cron y el límite sube de 5 a 50 peticiones/30 s.
$nvd_clave = getenv('NVD_API_KEY') ?: '';
$nvd_pausa_us = $nvd_clave ? 1000000 : 6500000;

// Opcional: con TELEGRAM_BOT_TOKEN y al menos un chat, el sync avisa por Telegram.
// Sin eso corre igual y no avisa.
$tg_token = getenv('TELEGRAM_BOT_TOKEN') ?: '';

// Una sala por criticidad, más la de lo que ya se está explotando. Cada
// vulnerabilidad va solo a la suya, y la sala que no tenga chat no recibe nada:
// así se silencia el ruido sin perder las que importan. Ver sala_de() y destino_de().
//
// El valor es un chat ('-1001234567890') o un tema de un grupo con foro
// ('-1001234567890:7'), que permite tener todas las salas en un solo grupo.
$tg_salas = [
    'kev'         => getenv('TELEGRAM_CHAT_KEV') ?: '',          // explotándose ya (CISA KEV / EU KEV)
    'critica'     => getenv('TELEGRAM_CHAT_CRITICAS') ?: '',     // CVSS >= 9.0
    'alta'        => getenv('TELEGRAM_CHAT_ALTAS') ?: '',        // 7.0 - 8.9
    'media'       => getenv('TELEGRAM_CHAT_MEDIAS') ?: '',       // 4.0 - 6.9
    'baja'        => getenv('TELEGRAM_CHAT_BAJAS') ?: '',        // < 4.0
    'sin_puntuar' => getenv('TELEGRAM_CHAT_SIN_PUNTUAR') ?: '',  // aún sin CVSS de nadie
];

// Respaldo para las salas sin chat propio, que es el montaje de un solo grupo.
$tg_chat   = getenv('TELEGRAM_CHAT_ID') ?: '';
$tg_umbral = (float) (getenv('TELEGRAM_UMBRAL') ?: '7');  // solo filtra lo que cae en el respaldo

/**
 * Modo rápido: el listado de la EUVD, los títulos y CWE nuevos de cve.org y el
 * KEV; las CWE del NVD y la EPSS se leen de la caché en vez de pedirse.
 *
 * Tiene sentido porque las fuentes no cambian al mismo ritmo: el modelo EPSS se
 * recalcula una vez al día y el NVD tarda en enriquecer, mientras que lo único
 * que trae vulnerabilidades nuevas es el listado. Así se puede pasar cada 15
 * minutos por 40 s en vez de por 190 s, y dejar la pasada completa cada 6 horas.
 */
$rapido = in_array('--rapido', $argv ?? [], true) || getenv('SYNC_RAPIDO') === '1';

// El freno de mano. Con la pausa puesta la pasada sigue haciendo todo lo demás
// —descargar, enriquecer y publicar la web— pero no manda, no edita y no borra
// nada en Telegram: se limita a anotar en silencio lo que va saliendo, igual que
// una siembra. Es a propósito que no encole: una pausa que guarda todo lo que no
// mandó es una bomba de relojería, y al quitarla saldrían de golpe los avisos de
// los días que estuvo parada.
define('TG_EN_PAUSA', (bool) preg_match('/^(1|si|sí|true|on)$/i', getenv('TELEGRAM_PAUSA') ?: ''));

// Cuánto se guarda una entrada en el registro después de dejar de aparecer. No es
// la caducidad del feed —esa son VENTANA_DIAS desde que se vio— sino la memoria de
// "esto ya lo conocía": si se olvidara antes de que la EUVD deje de devolverla, la
// pasada siguiente la tomaría por nueva y volvería a ingerirla.
const VISTAS_OLVIDO_DIAS = 14;

// Cuánto hacia atrás se siembra lo que solo consta en VulnCheck. Son ~3.500 CVE
// que la EUVD no marca, casi todas de hace años: pedir sus fichas una a una son
// veinte minutos por pasada y triplicar la tabla con cosas que no son noticia.
// Lo que hace falta es lo que acaba de entrar en el catálogo, que es lo único
// que es_noticia() deja avisar; la ventana del feed da margen sobre esos 7 días.
const VULNCHECK_SIEMBRA_DIAS = VENTANA_DIAS;

$destino = __DIR__ . '/data/cves.json';
$cerrojo_ruta = __DIR__ . '/.sync.lock';
$cache_meta   = __DIR__ . '/data/cve_meta.json';   // título y CWE de cve.org
$cache_cwes   = __DIR__ . '/data/cwes_nvd.json';
$cache_epss   = __DIR__ . '/data/epss.json';
// Las fichas de lo explotado que cae fuera de la ventana. Sin esta caché habría
// que volver a pedir ~1.300 fichas sueltas en cada pasada; con ella solo se piden
// las que entren nuevas en el catálogo, que son unas pocas por semana.
$cache_kev    = __DIR__ . '/data/kev_extra.json';
// Fuera de data/: ese directorio se publica y esto es estado interno, no un dato del feed.
$estado_telegram = __DIR__ . '/.notificado.json';
// La memoria del feed: qué entradas ha visto ya y cuándo vio cada una por primera
// vez. También fuera de data/, por lo mismo: es estado interno, no un dato.
$registro_vistas = __DIR__ . '/.vistas.json';

// ---------------------------------------------------------------- utilidades

function log_linea(string $msg): void
{
    fwrite(STDOUT, '[' . gmdate('Y-m-d H:i:s') . 'Z] ' . $msg . PHP_EOL);
}

/**
 * Escritura atómica: primero temporal, luego rename. Así la web nunca lee
 * un JSON a medias si el cron salta mientras alguien está navegando.
 */
function escribir_json(string $ruta, array $datos): bool
{
    $directorio = dirname($ruta);
    if (!is_dir($directorio) && !mkdir($directorio, 0755, true) && !is_dir($directorio)) {
        log_linea("No pude crear {$directorio}");
        return false;
    }

    $json = json_encode($datos, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $temporal = $ruta . '.tmp';

    if ($json === false || file_put_contents($temporal, $json) === false) {
        log_linea("Fallo al escribir {$temporal}");
        return false;
    }

    return rename($temporal, $ruta);
}

function pedir(string $url, array $cabeceras = []): ?array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => TIMEOUT,
        CURLOPT_HTTPHEADER     => array_merge(['Accept: application/json'], $cabeceras),
        CURLOPT_USERAGENT      => 'euvd-feed/1.0',
    ]);

    $cuerpo = curl_exec($ch);
    $codigo = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error  = curl_error($ch);
    curl_close($ch);

    if ($cuerpo === false) {
        log_linea("cURL falló: {$error}");
        return null;
    }
    if ($codigo !== 200) {
        log_linea("HTTP {$codigo} en {$url}");
        return null;
    }

    $json = json_decode((string) $cuerpo, true);
    return is_array($json) ? $json : null;
}

/**
 * La API devuelve fechas tipo "Apr 15, 2025, 8:30:58 PM".
 * Las pasamos a ISO 8601 para poder ordenar y formatear sin sorpresas.
 */
function fecha_iso(?string $bruta): ?string
{
    if ($bruta === null || trim($bruta) === '') {
        return null;
    }
    $ts = strtotime(str_replace(',', '', $bruta));
    return $ts === false ? null : gmdate('c', $ts);
}

function severidad(?float $score): string
{
    if ($score === null || $score <= 0.0) return 'sin_puntuar';
    if ($score >= 9.0) return 'critica';
    if ($score >= 7.0) return 'alta';
    if ($score >= 4.0) return 'media';
    return 'baja';
}

/** El CVE viene dentro de `aliases`, separado por saltos de línea. */
function extraer_cve(?string $aliases): ?string
{
    if (!$aliases) return null;
    return preg_match('/CVE-\d{4}-\d{4,}/', $aliases, $m) ? $m[0] : null;
}

/** @return string[] */
function nombres(array $lista, string $clave): array
{
    $salida = [];
    foreach ($lista as $entrada) {
        $nombre = $entrada[$clave]['name'] ?? null;
        if (is_string($nombre) && trim($nombre) !== '') {
            $salida[] = trim($nombre);
        }
    }
    return array_values(array_unique($salida));
}

/** Respaldo cuando cve.org no da título: primera frase de la descripción, recortada. */
function nombre_corto(string $descripcion): string
{
    $texto = trim(preg_replace('/\s+/', ' ', $descripcion));
    if ($texto === '') return 'Sin descripción';

    $corte = preg_split('/(?<=[.;])\s/', $texto, 2);
    $frase = $corte[0] ?? $texto;

    if (mb_strlen($frase) > 140) {
        $frase = mb_substr($frase, 0, 137) . '…';
    }
    return $frase;
}

/**
 * Normaliza una debilidad a ['id' => 'CWE-79', 'nombre' => 'Improper Neutralization…'].
 * El id puede venir en su propio campo (`cweId` en cve.org) o solo como prefijo del
 * texto. Lo que no lleve número —"n/a", "Other", los NVD-CWE-noinfo— se descarta:
 * un hueco es más honesto que una etiqueta que no dice nada.
 *
 * @return array{id:string,nombre:?string}|null
 */
function normalizar_cwe(mixed $id, mixed $descripcion): ?array
{
    $texto = is_string($descripcion) ? trim($descripcion) : '';
    $clave = is_string($id) ? trim($id) : '';

    if (!preg_match('/^CWE-\d+$/', $clave)) {
        $clave = preg_match('/^CWE-(\d+)/', $texto, $m) ? 'CWE-' . $m[1] : '';
    }
    if ($clave === '') return null;

    $nombre = trim(preg_replace('/^CWE-\d+[\s:.-]*/', '', $texto));
    if ($nombre === '' || preg_match('#^(n/a|other|unknown)$#i', $nombre)) {
        $nombre = null;
    }

    return ['id' => $clave, 'nombre' => $nombre];
}

/**
 * Une varias listas de CWE quitando repetidos y quedándose con la que trae nombre.
 *
 * @param  array<int,?array{id:string,nombre:?string}> ...$listas
 * @return array<int,array{id:string,nombre:?string}>
 */
function fusionar_cwes(array ...$listas): array
{
    $mapa = [];
    foreach ($listas as $lista) {
        foreach ($lista as $cwe) {
            if ($cwe === null) continue;
            $previo = $mapa[$cwe['id']] ?? null;
            if ($previo === null || ($previo['nombre'] === null && $cwe['nombre'] !== null)) {
                $mapa[$cwe['id']] = $cwe;
            }
        }
    }
    return array_values($mapa);
}

/**
 * Las CWE del registro CVE 5.x, tanto del CNA como de los enriquecedores (ADP).
 *
 * @return array<int,array{id:string,nombre:?string}>
 */
function cwes_de_cve_org(array $json): array
{
    $adp = $json['containers']['adp'] ?? [];
    $contenedores = array_merge(
        [$json['containers']['cna'] ?? null],
        is_array($adp) ? $adp : []
    );

    $salida = [];
    foreach ($contenedores as $contenedor) {
        foreach ($contenedor['problemTypes'] ?? [] as $tipo) {
            foreach ($tipo['descriptions'] ?? [] as $d) {
                if (isset($d['type']) && $d['type'] !== 'CWE') continue;
                $salida[] = normalizar_cwe($d['cweId'] ?? null, $d['description'] ?? null);
            }
        }
    }
    return fusionar_cwes($salida);
}

/**
 * Baja de cve.org el título oficial (`containers.cna.title`) y las CWE de una lista de CVE,
 * con CONCURRENCIA_TITULOS peticiones en vuelo. El título es opcional en el
 * esquema CVE 5.x, y un CVE recién reservado da 404 aunque la EUVD ya lo liste:
 * los que fallen sencillamente no salen en el array devuelto.
 *
 * @param  string[] $cves
 * @return array<string,array{titulo:?string,cwes:array<int,array{id:string,nombre:?string}>}>
 */
function pedir_registros_cve(array $cves): array
{
    $cves = array_values($cves);
    if ($cves === []) return [];

    $salida  = [];
    $multi   = curl_multi_init();
    $activos = [];   // id del handle => CVE
    $indice  = 0;

    $encolar = static function () use (&$indice, &$activos, $cves, $multi): void {
        if ($indice >= count($cves)) return;

        $cve = $cves[$indice++];
        $ch  = curl_init(API_CVE . $cve);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => TIMEOUT,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_USERAGENT      => 'euvd-feed/1.0',
        ]);
        curl_multi_add_handle($multi, $ch);
        $activos[spl_object_id($ch)] = $cve;
    };

    for ($i = 0; $i < CONCURRENCIA_TITULOS; $i++) {
        $encolar();
    }

    $corriendo = 0;
    do {
        curl_multi_exec($multi, $corriendo);
        curl_multi_select($multi, 1.0);

        while (($info = curl_multi_info_read($multi)) !== false) {
            $ch  = $info['handle'];
            $id  = spl_object_id($ch);
            $cve = $activos[$id] ?? null;

            if ($cve !== null && (int) curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) {
                $json = json_decode((string) curl_multi_getcontent($ch), true);
                if (is_array($json)) {
                    $titulo = $json['containers']['cna']['title'] ?? null;
                    $salida[$cve] = [
                        'titulo' => (is_string($titulo) && trim($titulo) !== '') ? trim($titulo) : null,
                        'cwes'   => cwes_de_cve_org($json),
                    ];
                }
            }

            unset($activos[$id]);
            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);
            $encolar();
        }
    } while ($corriendo > 0 || $activos !== []);

    curl_multi_close($multi);
    return $salida;
}

/** Lee una caché de disco; si no existe o está corrupta, se rehace sola. */
function leer_cache(string $ruta): array
{
    if (!is_readable($ruta)) return [];
    $previo = json_decode((string) file_get_contents($ruta), true);
    return is_array($previo) ? $previo : [];
}

/**
 * Pone en `nombre` el título de cve.org y en `cwes` las debilidades del registro.
 * Solo pedimos los CVE que no estén ya en caché: la ventana se solapa entre
 * ejecuciones y no tiene sentido bajar 2.500 registros cada hora. Los fallos de
 * red no se cachean, así se reintentan en la pasada siguiente.
 *
 * @param array<int,array<string,mixed>> $filas
 */
function completar_meta(array &$filas, string $cache_ruta): void
{
    $cache = leer_cache($cache_ruta);

    $pendientes = [];
    foreach ($filas as $fila) {
        $cve = $fila['cve'];
        if (is_string($cve) && !isset($cache[$cve])) {
            $pendientes[$cve] = true;
        }
    }
    $pendientes = array_keys($pendientes);

    log_linea('cve.org: ' . count($cache) . ' registros en caché, ' . count($pendientes) . ' por pedir');

    foreach (array_chunk($pendientes, TANDA_TITULOS) as $n => $tanda) {
        $cache += pedir_registros_cve($tanda);
        log_linea('  ' . min(($n + 1) * TANDA_TITULOS, count($pendientes)) . '/' . count($pendientes) . ' registros de cve.org');
    }

    // Los que no tengan título se quedan con la primera frase de la descripción.
    $vigentes = [];
    $con_titulo = 0;
    $con_cwe    = 0;
    foreach ($filas as &$fila) {
        $registro = is_string($fila['cve']) ? ($cache[$fila['cve']] ?? null) : null;
        if (!is_array($registro)) continue;

        if (($registro['titulo'] ?? null) !== null) {
            $fila['nombre'] = $registro['titulo'];
            $con_titulo++;
        }
        if (($registro['cwes'] ?? []) !== []) {
            $fila['cwes'] = fusionar_cwes($registro['cwes']);
            $con_cwe++;
        }
        $vigentes[$fila['cve']] = $registro;
    }
    unset($fila);

    // Reescribimos la caché solo con lo que sigue en ventana: si no, crece sin fin.
    escribir_json($cache_ruta, $vigentes);
    log_linea($con_titulo . ' de ' . count($filas) . ' filas con título de cve.org, ' . $con_cwe . ' con CWE');
}

// ---------------------------------------------------------------- CWE del NVD

/**
 * Las CWE que el NVD asigna a una CVE. Vienen sin nombre, solo el identificador.
 *
 * @return array<int,array{id:string,nombre:?string}>
 */
function cwes_de_nvd(?array $weaknesses): array
{
    $salida = [];
    foreach ($weaknesses ?? [] as $debilidad) {
        foreach ($debilidad['description'] ?? [] as $d) {
            $salida[] = normalizar_cwe($d['value'] ?? null, null);
        }
    }
    return fusionar_cwes($salida);
}

/**
 * Baja del NVD las CWE de todas las CVE publicadas en un rango de fechas, paginando.
 *
 * @return array<string,array<int,array{id:string,nombre:?string}>>
 */
function pedir_cwes_nvd(string $desde_iso, string $hasta_iso, string $clave, int $pausa_us): array
{
    $cabeceras = $clave !== '' ? ['apiKey: ' . $clave] : [];
    $salida    = [];

    for ($pagina = 0; $pagina < NVD_MAX_PAGINAS; $pagina++) {
        $url = API_NVD . '?' . http_build_query([
            'pubStartDate'   => $desde_iso,
            'pubEndDate'     => $hasta_iso,
            'resultsPerPage' => NVD_PAGE,
            'startIndex'     => $pagina * NVD_PAGE,
        ]);

        $respuesta = pedir($url, $cabeceras);
        if ($respuesta === null) {
            log_linea('El NVD falló; me quedo con las CWE que ya tenga.');
            break;
        }

        $vulns = $respuesta['vulnerabilities'] ?? [];
        if (!is_array($vulns) || count($vulns) === 0) {
            break;
        }

        foreach ($vulns as $entrada) {
            $id = $entrada['cve']['id'] ?? null;
            if (!is_string($id)) continue;

            $cwes = cwes_de_nvd($entrada['cve']['weaknesses'] ?? null);
            if ($cwes !== []) {
                $salida[$id] = $cwes;
            }
        }

        $total = (int) ($respuesta['totalResults'] ?? 0);
        log_linea('NVD página ' . $pagina . ': ' . count($vulns) . ' CVE (con CWE acumuladas: ' . count($salida) . ')');

        if (($pagina + 1) * NVD_PAGE >= $total) {
            break;
        }
        usleep($pausa_us);
    }

    return $salida;
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
 *
 * @param array<int,array<string,mixed>> $filas
 */
function completar_cwes_nvd(array &$filas, string $cache_ruta, string $clave, int $pausa_us, bool $rapido): void
{
    $cache = leer_cache($cache_ruta);

    $desde_iso = gmdate('Y-m-d\TH:i:s.000', strtotime('-' . (VENTANA_DIAS + NVD_MARGEN_DIAS) . ' days'));
    $hasta_iso = gmdate('Y-m-d\TH:i:s.000');

    // En modo rápido no se pregunta al NVD: es la fase más lenta con diferencia y
    // el enriquecimiento no va a cambiar en quince minutos.
    // Lo recién bajado manda sobre la caché.
    $por_cve = $rapido
        ? $cache
        : pedir_cwes_nvd($desde_iso, $hasta_iso, $clave, $pausa_us) + $cache;

    $vigentes = [];
    $con_nvd  = 0;
    foreach ($filas as &$fila) {
        $cve  = $fila['cve'];
        $cwes = is_string($cve) ? ($por_cve[$cve] ?? null) : null;
        if ($cwes === null || $cwes === []) continue;

        // El NVD solo completa las CWE que cve.org no haya dado: allí vienen con nombre.
        $fila['cwes']   = fusionar_cwes($fila['cwes'], $cwes);
        $vigentes[$cve] = $cwes;
        $con_nvd++;
    }
    unset($fila);

    // Igual que con los títulos: la caché se queda solo con lo que sigue en ventana.
    escribir_json($cache_ruta, $vigentes);
    log_linea($con_nvd . ' de ' . count($filas) . ' filas con CWE del NVD'
        . ($rapido ? ' (de caché)' : ''));
}

// ---------------------------------------------------------------- EPSS de FIRST

/**
 * Probabilidad de que una CVE se explote en los próximos 30 días, según el modelo
 * EPSS de FIRST. Se pide en tandas de 100 porque es lo que admite la API por
 * petición; una CVE recién publicada aún no tiene puntuación y no vuelve en la
 * respuesta.
 *
 * @param  string[] $cves
 * @return array<string,array{epss:float,percentil:?float,fecha:?string}>
 */
function pedir_epss(array $cves): array
{
    $salida = [];
    $hechos = 0;

    foreach (array_chunk($cves, EPSS_TANDA) as $tanda) {
        $url = API_EPSS . '?' . http_build_query([
            'cve'   => implode(',', $tanda),
            'limit' => EPSS_TANDA,
        ]);

        $respuesta = pedir($url);
        if ($respuesta === null) {
            log_linea('FIRST falló; me quedo con las puntuaciones EPSS que ya tenga.');
            break;
        }

        foreach ($respuesta['data'] ?? [] as $entrada) {
            $cve = $entrada['cve'] ?? null;
            if (!is_string($cve) || !is_numeric($entrada['epss'] ?? null)) {
                continue;
            }
            $percentil = $entrada['percentile'] ?? null;
            $fecha     = $entrada['date'] ?? null;

            $salida[$cve] = [
                'epss'      => (float) $entrada['epss'],
                'percentil' => is_numeric($percentil) ? (float) $percentil : null,
                'fecha'     => is_string($fecha) ? $fecha : null,
            ];
        }

        $hechos += count($tanda);
        log_linea('EPSS ' . $hechos . '/' . count($cves) . ' (con puntuación: ' . count($salida) . ')');

        if ($hechos < count($cves)) {
            usleep(EPSS_PAUSA_US);
        }
    }

    return $salida;
}

/**
 * Pone la EPSS oficial de FIRST en cada fila.
 *
 * La EUVD trae un campo epss, pero llega en porcentaje y vale 0 en todo lo recién
 * publicado, que es justo lo que enseña este feed: por eso se pide a la fuente.
 * Aquí no vale cachear y no volver a preguntar como con los títulos, porque el
 * modelo se recalcula a diario: se piden todas y la caché solo sirve de red por
 * si FIRST no responde.
 *
 * @param array<int,array<string,mixed>> $filas
 */
function completar_epss(array &$filas, string $cache_ruta, bool $rapido): void
{
    $cache = leer_cache($cache_ruta);

    $cves = [];
    foreach ($filas as $fila) {
        if (is_string($fila['cve'])) $cves[$fila['cve']] = true;
    }
    $cves = array_keys($cves);

    // En modo rápido tiramos de caché: el modelo de FIRST se publica una vez al día,
    // así que preguntarlo cada quince minutos es bajar los mismos números.
    log_linea($rapido
        ? 'EPSS: uso la caché, no pregunto a FIRST'
        : 'EPSS: ' . count($cves) . ' CVE por consultar a FIRST');

    // Lo recién bajado manda sobre la caché.
    $epss = $rapido ? $cache : pedir_epss($cves) + $cache;

    $vigentes = [];
    foreach ($filas as &$fila) {
        $cve  = $fila['cve'];
        $dato = is_string($cve) ? ($epss[$cve] ?? null) : null;
        if ($dato === null) continue;

        $fila['epss']          = $dato['epss'];
        $fila['epssPercentil'] = $dato['percentil'] ?? null;
        $fila['epssFecha']     = $dato['fecha'] ?? null;
        $fila['origenEpss']    = 'first';
        $vigentes[$cve]        = $dato;
    }
    unset($fila);

    escribir_json($cache_ruta, $vigentes);
    log_linea(count($vigentes) . ' de ' . count($filas) . ' filas con EPSS de FIRST'
        . ($rapido ? ' (de caché)' : ''));
}

// ---------------------------------------------------------------- KEV

/**
 * El catálogo de lo que ya se está explotando: CISA KEV y EU KEV, que la EUVD
 * consolida y sirve de una vez en /api/kev/dump. Una sola petición, sin paginar.
 *
 * Es el complemento de la EPSS, no un duplicado: la EPSS estima la probabilidad
 * de que alguien la explote, el KEV dice que ya lo está haciendo. Y no se parecen
 * (de las que caen en KEV, la mayoría anda por debajo del 1 % de EPSS), así que
 * ordenar por EPSS las entierra.
 *
 * Se pide una vez por pasada y el resultado lo usan sembrar_kev() y completar_kev().
 *
 * @return array<int,array<string,mixed>>|null
 */
function pedir_kev(): ?array
{
    $dump = pedir(API_KEV);
    $entradas = null;

    if (is_array($dump)) {
        $entradas = isset($dump[0]) ? $dump : ($dump['items'] ?? null);
    }
    if (!is_array($entradas)) {
        log_linea('KEV: no pude leer el catálogo.');
        return null;
    }
    return $entradas;
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
 * ver mensaje_telegram(). Las fechas van en YYYY-MM-DD, como las de la EUVD, para
 * que las dos se puedan comparar.
 *
 * @return array<string,array<string,mixed>>|null
 */
function pedir_vulncheck_kev(): ?array
{
    $token = getenv('VULNCHECK_API_TOKEN') ?: '';
    if ($token === '') {
        log_linea('VulnCheck: sin VULNCHECK_API_TOKEN, no pido el catálogo.');
        return null;
    }

    $por_cve = [];
    $total   = null;

    for ($pagina = 1; $pagina <= VULNCHECK_MAX_PAGINAS; $pagina++) {
        $url = API_VULNCHECK_KEV . '?' . http_build_query(['limit' => VULNCHECK_PAGE, 'page' => $pagina]);
        $respuesta = pedir($url, ['Authorization: Bearer ' . $token]);

        if ($respuesta === null) {
            log_linea("VulnCheck: falló la página {$pagina}; me quedo sin catálogo esta pasada.");
            return null;
        }

        $datos = is_array($respuesta['data'] ?? null) ? $respuesta['data'] : [];
        if ($total === null && isset($respuesta['_meta']['total_documents'])) {
            $total = (int) $respuesta['_meta']['total_documents'];
        }

        foreach ($datos as $e) {
            $ficha = ficha_vulncheck($e);
            $cves  = is_array($e['cve'] ?? null) ? $e['cve'] : [];

            foreach ($cves as $cve) {
                if (!is_string($cve) || $cve === '') continue;

                // Si un CVE aparece dos veces manda la ficha más antigua: lo que
                // importa es desde cuándo consta explotado, que es lo que mira
                // es_noticia().
                $antes = $por_cve[$cve]['fecha'] ?? null;
                if (is_string($antes) && $antes !== '' && ($ficha['fecha'] === null || $antes <= $ficha['fecha'])) continue;

                $por_cve[$cve] = $ficha;
            }
        }

        if (count($datos) < VULNCHECK_PAGE) break;
        usleep(PAUSA_US);
    }

    if ($total !== null && $total > VULNCHECK_MAX_PAGINAS * VULNCHECK_PAGE) {
        log_linea('VulnCheck: el catálogo tiene ' . $total . ' entradas y el tier community solo deja bajar '
            . (VULNCHECK_MAX_PAGINAS * VULNCHECK_PAGE) . '. Falta parte, y lo que falte no se avisa.');
    }

    log_linea('VulnCheck KEV: ' . count($por_cve) . ' CVE explotadas en el catálogo');
    return $por_cve;
}

/**
 * Una entrada del catálogo, con los nombres del feed. Es lo que acaba en el
 * mensaje de Telegram, así que se queda con todo lo que el catálogo sabe y el
 * resto de fuentes no: si CISA lo confirmó también y cuándo, si hay campañas de
 * ransomware usándola, el plazo de parcheo y las pruebas de explotación.
 *
 * @param array<string,mixed> $e
 * @return array<string,mixed>
 */
function ficha_vulncheck(array $e): array
{
    $solo_dia = static fn (mixed $v): ?string =>
        (is_string($v) && $v !== '') ? substr($v, 0, 10) : null;

    $evidencias = [];
    foreach ((is_array($e['vulncheck_reported_exploitation'] ?? null) ? $e['vulncheck_reported_exploitation'] : []) as $r) {
        $url = $r['url'] ?? null;
        if (is_string($url) && preg_match('#^https?://#', $url) === 1) $evidencias[] = $url;
    }

    $cwes = [];
    foreach ((is_array($e['cwes'] ?? null) ? $e['cwes'] : []) as $c) {
        if (is_string($c) && preg_match('/^CWE-\d+$/', $c) === 1) $cwes[] = $c;
    }

    return [
        'fecha'       => $solo_dia($e['date_added'] ?? null),
        'cisaFecha'   => $solo_dia($e['cisa_date_added'] ?? null),
        'plazo'       => $solo_dia($e['dueDate'] ?? null),
        'nombre'      => is_string($e['vulnerabilityName'] ?? null) ? trim($e['vulnerabilityName']) : '',
        'descripcion' => is_string($e['shortDescription'] ?? null) ? trim($e['shortDescription']) : '',
        'accion'      => is_string($e['required_action'] ?? null) ? trim($e['required_action']) : '',
        'vendor'      => is_string($e['vendorProject'] ?? null) ? trim($e['vendorProject']) : '',
        'producto'    => is_string($e['product'] ?? null) ? trim($e['product']) : '',
        'cwes'        => array_values(array_unique($cwes)),
        'ransomware'  => ($e['knownRansomwareCampaignUse'] ?? null) === 'Known',
        'canarios'    => ($e['reported_exploited_by_vulncheck_canaries'] ?? null) === true,
        'evidencias'  => array_values(array_unique($evidencias)),
    ];
}

/**
 * La puntuación, el vector, las CWE y la fecha de publicación de un CVE, del NVD
 * que sirve el propio VulnCheck. Es lo único del mensaje que el catálogo de KEV
 * no trae, y se pide de una en una porque solo hace falta para lo que se manda:
 * con el filtro puesto son unos pocos por pasada, muy lejos de las 1.000
 * peticiones por minuto que deja el tier community.
 *
 * @return array<string,mixed>|null
 */
function pedir_vulncheck_nvd(string $cve): ?array
{
    $token = getenv('VULNCHECK_API_TOKEN') ?: '';
    if ($token === '') return null;

    $respuesta = pedir(API_VULNCHECK_NVD . '?' . http_build_query(['cve' => $cve]),
        ['Authorization: Bearer ' . $token]);
    $ficha = is_array($respuesta['data'][0] ?? null) ? $respuesta['data'][0] : null;
    if ($ficha === null) return null;

    // De las métricas manda la versión más alta que traiga, y a igualdad la del
    // asignador: es el mismo criterio con el que el NVD enseña una sola.
    $mejor = null;
    foreach ((is_array($ficha['metrics'] ?? null) ? $ficha['metrics'] : []) as $clave => $lista) {
        if (!str_starts_with((string) $clave, 'cvssMetric') || !is_array($lista)) continue;

        foreach ($lista as $m) {
            $d = $m['cvssData'] ?? null;
            if (!is_array($d) || !is_numeric($d['baseScore'] ?? null)) continue;

            $version  = (float) ($d['version'] ?? 0);
            $primaria = ($m['type'] ?? null) === 'Primary';
            if ($mejor !== null
                && !($version > $mejor['version'] || ($version === $mejor['version'] && $primaria && !$mejor['primaria']))) {
                continue;
            }
            // Los dos subíndices cuelgan de la métrica, no de cvssData, y se cogen
            // de la misma que da el score: mezclarlos con los de otra sería sumar
            // peras y manzanas. El CVSS 4.0 no los tiene, así que ahí van a null.
            $mejor = [
                'version'        => $version,
                'primaria'       => $primaria,
                'score'          => (float) $d['baseScore'],
                'vector'         => is_string($d['vectorString'] ?? null) ? $d['vectorString'] : null,
                'explotabilidad' => is_numeric($m['exploitabilityScore'] ?? null) ? (float) $m['exploitabilityScore'] : null,
                'impacto'        => is_numeric($m['impactScore'] ?? null) ? (float) $m['impactScore'] : null,
            ];
        }
    }

    $cwes = [];
    foreach ((is_array($ficha['weaknesses'] ?? null) ? $ficha['weaknesses'] : []) as $w) {
        foreach ((is_array($w['description'] ?? null) ? $w['description'] : []) as $d) {
            $v = $d['value'] ?? null;
            if (is_string($v) && preg_match('/^CWE-\d+$/', $v) === 1) $cwes[] = $v;
        }
    }

    return [
        'score'          => $mejor['score'] ?? null,
        'cvss'           => $mejor !== null ? (string) $mejor['version'] : null,
        'vector'         => $mejor['vector'] ?? null,
        'explotabilidad' => $mejor['explotabilidad'] ?? null,
        'impacto'        => $mejor['impacto'] ?? null,
        // Sin recortar: el mensaje enseña también la hora. El NVD la publica en
        // UTC y sin marca horaria, que es justo por lo que el mensaje lo dice.
        'publicado'      => is_string($ficha['published'] ?? null) ? $ficha['published'] : null,
        'cwes'           => array_values(array_unique($cwes)),
    ];
}

/**
 * Una sola petición por CVE y pasada: entre un envío y la edición del mismo
 * mensaje no hace falta volver a preguntar.
 *
 * @return array<string,mixed>|null
 */
function datos_vulncheck_nvd(?string $cve): ?array
{
    static $vistas = [];

    if (!is_string($cve) || $cve === '') return null;
    if (!array_key_exists($cve, $vistas)) $vistas[$cve] = pedir_vulncheck_nvd($cve);

    return $vistas[$cve];
}

/**
 * Mete en el listado lo explotado que la ventana no alcanza.
 *
 * La búsqueda de la EUVD filtra por fecha de publicación, así que una CVE
 * publicada en abril y explotada desde mayo no sale por ningún lado: ni en la web
 * ni en la sala de KEV de Telegram, por muy grave que sea. Y eso es justo lo que
 * no puede faltar, que es el único motivo por el que este feed pesa lo que pesa.
 *
 * completar_kev() no servía para esto porque solo marca lo ya descargado; aquí se
 * añaden filas, pidiendo la ficha suelta de cada una a /api/enisaid.
 *
 * El catálogo entero son ~1.300 entradas y casi ninguna cae en la ventana, así que
 * las fichas se guardan en su propia caché y solo se piden las que aún no estén.
 * En régimen son unas pocas por semana; la primera pasada sí paga las 1.300.
 *
 * La caché se poda con el catálogo, como las demás: lo que sale de KEV deja de
 * mantenerse y de publicarse, que es lo correcto (si CISA lo retira, aquí también).
 *
 * @param array<string,array<string,mixed>>      $registros
 * @param array<int,array<string,mixed>>|null    $entradas
 * @param array<string,string|null>|null         $vulncheck
 */
function sembrar_kev(array &$registros, ?array $entradas, string $cache_ruta, ?array $vulncheck = null): void
{
    if ($entradas === null && $vulncheck === null) {
        log_linea('KEV: sin catálogo, no siembro nada fuera de ventana.');
        return;
    }

    $cache = leer_cache($cache_ruta);

    // Lo que ya trajo la ventana no se vuelve a pedir, ni por su id de la EUVD ni
    // por su CVE: la ficha sería la misma y la de la ventana viene más fresca.
    $en_ventana = [];
    foreach ($registros as $fila) {
        $en_ventana[$fila['euvd']] = true;
        if (is_string($fila['cve'] ?? null)) $en_ventana[$fila['cve']] = true;
    }

    // La clave con la que se pide la ficha: el id de la EUVD para lo que trae su
    // catálogo y el CVE para lo que solo trae VulnCheck, que no da ids de la EUVD.
    // El endpoint /api/enisaid acepta las dos cosas, así que a partir de aquí da
    // igual de dónde venga cada una.
    $faltan  = [];
    $pedidas = [];
    foreach ($entradas ?? [] as $e) {
        $euvd = $e['euvdId'] ?? null;
        if (!is_string($euvd) || isset($en_ventana[$euvd])) continue;

        $cve = $e['cveId'] ?? null;
        if (is_string($cve) && isset($en_ventana[$cve])) continue;

        $faltan[] = $euvd;
        $pedidas[$euvd] = true;
        if (is_string($cve)) $pedidas[$cve] = true;
    }

    // De lo que solo tiene VulnCheck se siembra lo recién añadido y nada más; ver
    // VULNCHECK_SIEMBRA_DIAS. Sin esto, la mayoría de lo que VulnCheck marca antes
    // que CISA no llegaría a Telegram: son CVE de hace meses o años, no las alcanza
    // la ventana, y sin fila no hay aviso por muy explotadas que estén.
    $desde_siembra = time() - VULNCHECK_SIEMBRA_DIAS * 86400;
    $de_vulncheck  = 0;
    foreach ($vulncheck ?? [] as $cve => $ficha) {
        if (isset($en_ventana[$cve]) || isset($pedidas[$cve])) continue;

        $entrada = is_string($ficha['fecha'] ?? null) ? strtotime($ficha['fecha']) : false;
        if ($entrada === false || $entrada < $desde_siembra) continue;

        $faltan[] = $cve;
        $pedidas[$cve] = true;
        $de_vulncheck++;
    }

    $pendientes = [];
    foreach ($faltan as $clave) {
        if (!isset($cache[$clave])) $pendientes[] = $clave;
    }

    log_linea('KEV: ' . count($faltan) . ' explotadas fuera de la ventana (' . $de_vulncheck
        . ' solo en VulnCheck), ' . (count($faltan) - count($pendientes)) . ' en caché, '
        . count($pendientes) . ' por pedir');

    $hechas = 0;
    foreach ($pendientes as $clave) {
        $ficha = pedir(API_ENISAID . '?' . http_build_query(['id' => $clave]));
        $fila  = is_array($ficha) ? normalizar($ficha) : null;
        // Los fallos no se cachean: se reintentan en la pasada siguiente, igual que
        // en completar_meta(). Una ficha que no baja hoy baja dentro de diez minutos.
        if ($fila !== null) $cache[$clave] = $fila;
        if (++$hechas % 50 === 0) log_linea('  ' . $hechas . '/' . count($pendientes) . ' fichas de la EUVD');
        usleep(PAUSA_US);
    }

    // Poda: la caché se queda solo con lo que sigue en el catálogo.
    $vigentes = [];
    $sembradas = 0;
    foreach ($faltan as $clave) {
        $fila = $cache[$clave] ?? null;
        if (!is_array($fila)) continue;

        $vigentes[$clave] = $fila;
        // La marca es lo que distingue una fila traída por el catálogo de una traída
        // por la ventana. La usa notificar_telegram() para no vaciar el catálogo
        // entero en la sala de KEV la primera vez, y sale en el JSON porque es una
        // diferencia real: esta fila está aquí por estar explotada, no por reciente.
        $fila['fueraDeVentana'] = true;
        $registros[$fila['euvd']] = $fila;
        $sembradas++;
    }

    escribir_json($cache_ruta, $vigentes);
    log_linea('KEV: ' . $sembradas . ' filas añadidas fuera de la ventana');
}

/**
 * Marca con la fecha y las fuentes del catálogo las filas que están en él.
 *
 * @param array<int,array<string,mixed>>      $filas
 * @param array<int,array<string,mixed>>|null $entradas
 * @param array<string,string|null>|null      $vulncheck
 */
function completar_kev(array &$filas, ?array $entradas, ?array $vulncheck = null): void
{
    if ($entradas === null && $vulncheck === null) {
        log_linea('KEV: sin catálogo, las filas se quedan sin marcar.');
        return;
    }

    $por_cve  = [];
    $por_euvd = [];
    foreach ($entradas ?? [] as $e) {
        if (is_string($e['cveId'] ?? null))  $por_cve[$e['cveId']]   = $e;
        if (is_string($e['euvdId'] ?? null)) $por_euvd[$e['euvdId']] = $e;
    }

    $marcadas      = 0;
    $con_vulncheck = 0;
    foreach ($filas as &$fila) {
        $cve = $fila['cve'];
        $kev = (is_string($cve) ? ($por_cve[$cve] ?? null) : null) ?? ($por_euvd[$fila['euvd']] ?? null);
        // El catálogo de VulnCheck va por CVE: una fila sin CVE no se puede cruzar.
        $en_vulncheck = is_string($cve) && $vulncheck !== null && array_key_exists($cve, $vulncheck);
        if ($kev === null && !$en_vulncheck) continue;

        $fuentes = is_array($kev['sources'] ?? null) ? array_values($kev['sources']) : [];
        if ($en_vulncheck) $fuentes[] = 'vulncheck_kev';

        // De las dos fechas manda la más antigua: lo que importa es desde cuándo
        // consta explotada, no cuál de los dos catálogos se enteró el último. Es la
        // que mira es_noticia() para decidir si el primer aviso todavía es noticia.
        $fechas = [];
        if (is_string($kev['dateAdded'] ?? null) && $kev['dateAdded'] !== '') {
            $fechas[] = substr($kev['dateAdded'], 0, 10);
        }
        if ($en_vulncheck && is_string($vulncheck[$cve]['fecha'] ?? null) && $vulncheck[$cve]['fecha'] !== '') {
            $fechas[] = $vulncheck[$cve]['fecha'];
        }
        sort($fechas);

        $fila['kev'] = [
            'fecha'   => $fechas[0] ?? null,
            'fuentes' => $fuentes,
        ];
        $marcadas++;
        if ($en_vulncheck) $con_vulncheck++;
    }
    unset($fila);

    log_linea($marcadas . ' de ' . count($filas) . ' filas explotadas activamente ('
        . $con_vulncheck . ' confirmadas por VulnCheck, que es lo que llega a Telegram)');
}

// ---------------------------------------------------------------- normalización

function normalizar(array $item): ?array
{
    $euvd = $item['id'] ?? null;
    if (!is_string($euvd)) return null;

    $descripcion = trim((string) ($item['description'] ?? ''));
    $score       = isset($item['baseScore']) ? (float) $item['baseScore'] : null;
    $vendors     = nombres($item['enisaIdVendor'] ?? [], 'vendor');
    $productos   = nombres($item['enisaIdProduct'] ?? [], 'product');
    $cve         = extraer_cve($item['aliases'] ?? null);

    // La EUVD manda la EPSS en porcentaje (1.55 = 1,55 %) y con 0 cuando no la
    // tiene. Aquí se guarda como probabilidad 0-1, que es como la publica FIRST;
    // completar_epss() la sustituye por la del modelo en cuanto exista.
    $epss_euvd = isset($item['epss']) ? (float) $item['epss'] : null;
    $con_epss  = $epss_euvd !== null && $epss_euvd > 0.0;

    return [
        'euvd'        => $euvd,
        'cve'         => $cve,
        'nombre'      => nombre_corto($descripcion),  // lo pisa completar_meta() si cve.org tiene título
        'descripcion' => $descripcion,
        'vendor'      => $vendors[0] ?? null,
        'vendors'     => $vendors,
        'producto'    => $productos[0] ?? null,
        'productos'   => $productos,
        // La EUVD manda 0 cuando no hay CVSS: eso no es una puntuación, es un hueco,
        // y severidad() lo deja en "sin_puntuar". Es la única fuente del score.
        'score'       => $score,
        'severidad'   => severidad($score),
        'cvss'        => $item['baseScoreVersion'] ?? null,
        'vector'      => $item['baseScoreVector'] ?? null,
        'cwes'        => [],  // lo rellenan completar_meta() y completar_cwes_nvd()
        'kev'         => null,  // lo rellena completar_kev()
        'epss'        => $con_epss ? $epss_euvd / 100 : null,
        'epssPercentil' => null,  // solo lo da FIRST
        'epssFecha'     => null,
        'origenEpss'    => $con_epss ? 'euvd' : null,  // lo pisa completar_epss()
        'assigner'    => $item['assigner'] ?? null,
        'fecha'       => fecha_iso($item['datePublished'] ?? null),
        'actualizado' => fecha_iso($item['dateUpdated'] ?? null),
        'enlace'      => $cve
            ? 'https://nvd.nist.gov/vuln/detail/' . $cve
            : null,
    ];
}

// ---------------------------------------------------------------- Telegram

/**
 * Las salas, de menos a más prioridad. Este orden decide a qué sala va una fila
 * que encaja en varias —KEV manda sobre la puntuación— y, cuando una fila cambia
 * de sala, si la mudanza es hacia arriba o hacia abajo, que es lo único que
 * distingue el encabezado de un mensaje del otro.
 */
const TG_ORDEN = ['sin_puntuar', 'baja', 'media', 'alta', 'critica', 'kev'];


function prioridad_sala(string $sala): int
{
    $i = array_search($sala, TG_ORDEN, true);
    return $i === false ? 0 : (int) $i;
}

/**
 * Cada fila va a una sola sala: la de KEV si consta explotada, si no la de su severidad.
 *
 * @param array<string,mixed> $fila
 */
function sala_de(array $fila): string
{
    return is_array($fila['kev']) ? 'kev' : (string) $fila['severidad'];
}

/**
 * El filtro de Telegram: solo sale por el grupo lo que VulnCheck KEV da por
 * explotado. Todo lo demás sigue en la web (la tabla no cambia) pero no genera
 * mensajes, que es lo que se pidió: el grupo deja de ser un boletín de novedades
 * y pasa a ser la lista de lo que hay que parchear ya.
 *
 * Como todo lo que pasa este filtro tiene 'kev', sala_de() lo manda a la sala de
 * KEV: las salas por criticidad se quedan mudas mientras el filtro esté puesto.
 *
 * @param array<string,mixed> $fila
 */
function es_vulncheck_kev(array $fila): bool
{
    $fuentes = is_array($fila['kev']['fuentes'] ?? null) ? $fila['kev']['fuentes'] : [];
    return in_array('vulncheck_kev', $fuentes, true);
}

/**
 * La ficha del catálogo de VulnCheck de una fila, que es de donde sale su mensaje.
 *
 * @param array<string,mixed>                     $fila
 * @param array<string,array<string,mixed>>|null  $vulncheck
 * @return array<string,mixed>|null
 */
function ficha_de(array $fila, ?array $vulncheck): ?array
{
    $cve = $fila['cve'] ?? null;
    if (!is_string($cve) || $vulncheck === null) return null;

    return is_array($vulncheck[$cve] ?? null) ? $vulncheck[$cve] : null;
}

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
 *
 * @param array<string,mixed> $fila
 */
function es_noticia(array $fila, string $ahora_iso): bool
{
    if (($fila['fueraDeVentana'] ?? false) !== true) {
        return true;
    }

    $entrada = is_array($fila['kev'] ?? null) ? ($fila['kev']['fecha'] ?? null) : null;
    $t = is_string($entrada) ? strtotime($entrada) : false;
    if ($t === false) {
        return false;
    }

    return (strtotime($ahora_iso) - $t) <= TG_DIAS_NOTICIA * 86400;
}

// Las bandas de EPSS que cuentan como cambio. El modelo de FIRST se recalcula a
// diario y casi ninguna CVE conserva el mismo decimal de un día para otro: sin
// bandas habría que reeditar la ventana entera cada día, que son miles de
// llamadas contra un límite de veinte por minuto. Cruzar el 1, el 10 o el 50 %
// cambia lo que uno hace con una vulnerabilidad; el tercer decimal no.
const TG_BANDAS_EPSS = [0.01, 0.1, 0.5];

function banda_epss(mixed $v): int
{
    if (!is_int($v) && !is_float($v)) {
        return -1;
    }

    $n = 0;
    foreach (TG_BANDAS_EPSS as $banda) {
        if ((float) $v >= $banda) {
            $n++;
        }
    }

    return $n;
}

/**
 * Lo que decide si un mensaje ya publicado se queda como está. Va aparte del
 * texto a propósito: el texto lleva la EPSS con un decimal y la firma la lleva
 * por bandas, así que el mensaje enseña el número exacto del día en que se editó
 * pero un vaivén del 0,08 al 0,09 % no dispara una edición.
 *
 * SHA-1 sobre UTF-8 y en este orden exacto porque euvd_sync.mjs calcula la misma
 * firma: así el estado se puede pasar de una implementación a la otra sin que se
 * dispare una tanda de ediciones.
 *
 * @param array<string,mixed>      $fila
 * @param array<string,mixed>|null $vc
 */
function firma_fila(array $fila, string $sala, ?array $vc = null): string
{
    $cwes = [];
    foreach (($fila['cwes'] ?? []) as $c) {
        $cwes[] = (string) ($c['id'] ?? '');
    }

    $kev = '';
    if (is_array($fila['kev'] ?? null)) {
        $kev = (string) ($fila['kev']['fecha'] ?? '')
            . '|' . implode(',', $fila['kev']['fuentes'] ?? []);
    }

    // La ficha de VulnCheck va en la firma porque es de donde sale el texto del
    // mensaje: sin ella, cambiar el nombre o el plazo en el catálogo no reeditaría
    // nada. La puntuación no entra (se pide aparte, y solo de lo que se manda),
    // pero el score de la EUVD sí sigue estando, así que un reanálisis mueve la
    // firma igual y el mensaje se pone al día con él.
    $de_vulncheck = '';
    if ($vc !== null) {
        $de_vulncheck = implode("\u{0002}", [
            (string) ($vc['fecha'] ?? ''),
            (string) ($vc['cisaFecha'] ?? ''),
            (string) ($vc['plazo'] ?? ''),
            (string) ($vc['nombre'] ?? ''),
            (string) ($vc['descripcion'] ?? ''),
            (string) ($vc['accion'] ?? ''),
            (string) ($vc['vendor'] ?? ''),
            (string) ($vc['producto'] ?? ''),
            implode(',', $vc['cwes'] ?? []),
            ($vc['ransomware'] ?? false) ? 'R' : '',
            ($vc['canarios'] ?? false) ? 'C' : '',
        ]);
    }

    $partes = [
        $sala,
        (string) ($fila['score'] ?? ''),
        (string) banda_epss($fila['epss'] ?? null),
        $kev,
        implode(',', $cwes),
        (string) ($fila['nombre'] ?? ''),
        (string) ($fila['descripcion'] ?? ''),
        (string) ($fila['vendor'] ?? ''),
        (string) ($fila['producto'] ?? ''),
        (string) ($fila['fecha'] ?? ''),
        $de_vulncheck,
    ];

    return substr(sha1(implode("\u{0001}", $partes)), 0, 10);
}

/**
 * El chat de una sala, con $respaldo (TELEGRAM_CHAT_ID) para las que no tengan
 * el suyo. El respaldo solo recoge lo que pase el umbral: si no, quien tenga
 * montado un único chat pasaría de 183 mensajes al día a los 352 de la ventana
 * entera sin haber tocado nada. La excepción es KEV, que va siempre — que algo
 * se esté explotando importa aunque puntúe un 5.
 *
 * @param array<string,string> $salas
 * @param array<string,mixed>  $fila
 */
function destino_de(string $sala, array $fila, array $salas, string $respaldo, float $umbral): string
{
    if (($salas[$sala] ?? '') !== '') {
        return $salas[$sala];
    }
    if ($sala === 'kev') {
        return $respaldo;
    }
    return (is_numeric($fila['score']) && (float) $fila['score'] >= $umbral) ? $respaldo : '';
}

/**
 * Una sala puede apuntar a un tema de un grupo con foro: "-1001234567890:7" es
 * el tema 7 de ese grupo. Los identificadores de chat no llevan dos puntos, así
 * que partir por ahí no tiene ambigüedad.
 *
 * @return array{chat: string, hilo: ?int}
 */
function partir_destino(string $destino): array
{
    $corte = strpos($destino, ':');
    if ($corte === false) {
        return ['chat' => $destino, 'hilo' => null];
    }

    $hilo = substr($destino, $corte + 1);
    return [
        'chat' => substr($destino, 0, $corte),
        'hilo' => ctype_digit($hilo) ? (int) $hilo : null,
    ];
}

/** HTML es el parse_mode con menos que escapar: tres caracteres y se acabó. */
function escapar_html(?string $texto): string
{
    return htmlspecialchars((string) $texto, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * El dominio de una URL, sin el "www.", que es como se identifica una fuente de
 * un vistazo. Una URL rota devuelve null y su enlace no se enseña: sin dominio no
 * habría nada que poner de etiqueta.
 */
function dominio_de(string $url): ?string
{
    $host = parse_url($url, PHP_URL_HOST);
    if (!is_string($host) || $host === '') return null;

    $host = preg_replace('/^www\./', '', $host);
    return $host !== '' ? $host : null;
}

/**
 * Los mensajes van en inglés porque es el idioma de las fuentes: el título viene
 * de cve.org, las CWE de MITRE y los catálogos KEV de CISA y ENISA. Traducir la
 * mitad de cada mensaje dejaba frases a medio idioma.
 */
const TG_ETIQUETA_SALA = [
    'kev'         => 'KEV',
    'critica'     => 'Critical',
    'alta'        => 'High',
    'media'       => 'Medium',
    'baja'        => 'Low',
    'sin_puntuar' => 'Unscored',
];

// La descripción va en una cita: por encima de TG_DESC_PLEGABLE, Telegram la
// pliega y deja el resto del mensaje a la vista. El tope duro existe porque hay
// descripciones de 4.000 caracteres y un mensaje entero no puede pasar de 4.096.
const TG_DESC_PLEGABLE = 300;
const TG_DESC_MAX      = 3000;

const TG_CWE_VISIBLES  = 3;  // el mismo tope que la tabla; el resto va como "+n"

// A cuánto llega cada subíndice, que es lo que los hace legibles: un 1.8 de
// explotabilidad no dice nada, un "1.8 / 3.9" dice que cuesta explotarla. Los
// topes no son los mismos en cada versión del CVSS (la 2.0 puntúa los dos sobre
// 10) y la 4.0 no publica subíndices, así que ahí no sale la línea.
const TG_CVSS_TOPES = [
    '2.0' => ['explotabilidad' => 10.0, 'impacto' => 10.0],
    '3.0' => ['explotabilidad' => 3.9,  'impacto' => 6.0],
    '3.1' => ['explotabilidad' => 3.9,  'impacto' => 6.0],
];

// La acción recomendada es plantilla (19 textos distintos para 1.000 entradas)
// pero las hay de 520 caracteres. El tope está para que una futura más larga no
// se coma el margen hasta los 4.096 de un mensaje.
const TG_ACCION_MAX = 600;

// Las referencias con las que VulnCheck sostiene que se está explotando: unas
// son el informe de quien lo vio, otras el aviso del fabricante. Son las únicas
// que lleva el mensaje. El catálogo trae 32 de media por CVE, así que se cortan
// en dos (con eso ya se puede verificar) y el resto se resume en un "+n".
const TG_EVIDENCIAS_VISIBLES = 2;

/**
 * Un mensaje por vulnerabilidad, en cuatro bloques: cabecera con lo que se ve en
 * la notificación del móvil (criticidad, puntuación e identificador), título,
 * la alerta de explotación si la hay, los datos etiquetados y los enlaces.
 *
 * El identificador va en <code> para que Telegram lo ponga en monoespaciada y
 * se pueda copiar tocándolo, que es lo primero que se hace con un CVE.
 *
 * $previa solo llega cuando el mensaje se muda de sala, y entonces abre
 * diciéndolo: en la sala de KEV, la mitad de los mensajes son CVE de las que ya
 * se avisó hace días, y sin ese aviso parecen recién publicadas.
 *
 * $actualizado solo llega en las ediciones, y deja constancia de la hora. Sin eso
 * un mensaje cambiaría de contenido sin que se note: Telegram no marca de ninguna
 * manera los mensajes que edita un bot.
 *
 * @param array<string,mixed>      $fila
 * @param array<string,mixed>|null $previa
 */
function mensaje_telegram(array $fila, ?array $vc = null, ?array $nvd = null, ?array $previa = null, ?string $actualizado = null): string
{
    $marcas = [
        'critica'     => "\u{1F534} CRITICAL",
        'alta'        => "\u{1F7E0} HIGH",
        'media'       => "\u{1F7E1} MEDIUM",
        'baja'        => "\u{1F535} LOW",
        'sin_puntuar' => "\u{26AA} UNSCORED",
    ];

    $lineas = [];

    if ($previa !== null) {
        $sala_previa = (string) ($previa['sala'] ?? '');
        $antes  = TG_ETIQUETA_SALA[$sala_previa] ?? $sala_previa;
        $cuando = is_string($previa['fecha'] ?? null) ? ' on ' . substr($previa['fecha'], 0, 10) : '';
        // El mensaje de la sala anterior se borra al mudarse, así que este encabezado
        // no compite con nada: es lo único que queda de que ya se había avisado.
        $sube  = prioridad_sala(sala_de($fila)) > prioridad_sala($sala_previa);
        $marca = $sube
            ? "\u{2B06}\u{FE0F} <b>Escalated</b>"
            : "\u{2B07}\u{FE0F} <b>Downgraded</b>";
        $lineas[] = $marca . ' — previously reported as ' . $antes . $cuando;
        $lineas[] = '';
    }

    // El score del NVD que sirve VulnCheck; la severidad, del mismo corte que usa
    // la tabla, para que la marca de la cabecera diga lo mismo que el número.
    $score = is_numeric($nvd['score'] ?? null) ? (float) $nvd['score'] : null;
    $marca = $marcas[severidad($score)] ?? $marcas['sin_puntuar'];
    // Sin puntuación la cabecera se queda con la marca a secas: un CVSS 0.0 que
    // nadie ha puesto sería peor que no decir nada.
    $puntuacion = ($score !== null && $score > 0.0)
        ? ' · CVSS <b>' . number_format($score, 1, '.', '') . '</b>'
        : '';
    $lineas[] = $marca . $puntuacion . ' · <code>' . escapar_html($fila['cve'] ?? $fila['euvd']) . '</code>';

    // La descripción trae saltos de línea a media frase, así que se normaliza.
    $descripcion = trim(preg_replace('/\s+/', ' ', (string) ($vc['descripcion'] ?? '')));

    // El catálogo trae las dos cosas, pero a veces el nombre es el primer trozo de
    // la descripción: repetirlo sería enseñar dos veces la misma frase.
    $titulo  = trim((string) ($vc['nombre'] ?? ''));
    $recorte = trim(preg_replace('/…$/u', '', $titulo));

    if ($titulo !== '' && ($recorte === '' || !str_starts_with($descripcion, $recorte))) {
        $lineas[] = '<b>' . escapar_html($titulo) . '</b>';
    }

    // La alerta sale entera de la ficha de VulnCheck: su fecha, y la de CISA si
    // además la confirmó, que el propio catálogo trae en `cisa_date_added`.
    $fuentes = ['VulnCheck KEV'];
    if (is_string($vc['cisaFecha'] ?? null)) $fuentes[] = 'CISA KEV';
    $desde = is_string($vc['fecha'] ?? null) ? ', added ' . $vc['fecha'] : '';

    $lineas[] = '';
    $lineas[] = "\u{26A0}\u{FE0F} <b>Actively exploited</b> — "
        . escapar_html(implode(' · ', $fuentes)) . $desde;

    // Las dos cosas que separan lo urgente de lo muy urgente, y que no las da
    // ningún otro catálogo: si hay ransomware usándola y si la han visto entrar
    // en los señuelos de VulnCheck.
    if ($vc['ransomware'] ?? false) $lineas[] = "\u{1F512} <b>Known ransomware campaign use</b>";
    if ($vc['canarios'] ?? false)   $lineas[] = "\u{1F4E1} Exploitation seen by VulnCheck canaries";

    if ($descripcion !== '') {
        if (mb_strlen($descripcion) > TG_DESC_MAX) {
            $descripcion = preg_replace('/\s+\S*$/u', '', mb_substr($descripcion, 0, TG_DESC_MAX)) . '…';
        }
        $cita = mb_strlen($descripcion) > TG_DESC_PLEGABLE ? 'blockquote expandable' : 'blockquote';
        $lineas[] = '';
        $lineas[] = '<' . $cita . '>' . escapar_html($descripcion) . '</blockquote>';
    }

    // Datos etiquetados, en tres bloques separados por una línea en blanco: qué es,
    // cuánto pesa y qué fechas tiene. Siete etiquetas seguidas son un formulario y el
    // ojo no encuentra dónde mirar; en tres tandas de dos o tres, sí. Cada dato se
    // calla si no lo hay, y un bloque entero desaparece si se quedan todos callados.
    $identidad = [];
    $medidas   = [];
    $fechas    = [];

    if (($vc['vendor'] ?? '') !== '') {
        $identidad[] = '<b>Vendor:</b> ' . escapar_html($vc['vendor']);
    }
    if (($vc['producto'] ?? '') !== '' && $vc['producto'] !== ($vc['vendor'] ?? null)) {
        $identidad[] = '<b>Product:</b> ' . escapar_html($vc['producto']);
    }

    // Enlazadas a cwe.mitre.org, igual que en la tabla, y con el mismo tope de tres
    // visibles y un "+n" con el resto: en un mensaje de móvil, seis identificadores
    // seguidos ocupan más que todo lo demás junto.
    //
    // Mandan las del catálogo de KEV, que van a la causa de lo que se está
    // explotando; las del NVD entran solo si el catálogo no trae ninguna.
    $delKev = is_array($vc['cwes'] ?? null) ? $vc['cwes'] : [];
    $cwes   = array_values(array_filter(
        count($delKev) > 0 ? $delKev : (is_array($nvd['cwes'] ?? null) ? $nvd['cwes'] : []),
        static fn ($id): bool => is_string($id) && preg_match('/^CWE-\d+$/', $id) === 1
    ));

    if (count($cwes) > 0) {
        $enlazadas = [];
        foreach (array_slice($cwes, 0, TG_CWE_VISIBLES) as $id) {
            $enlazadas[] = '<a href="https://cwe.mitre.org/data/definitions/'
                . substr($id, 4) . '.html">' . $id . '</a>';
        }
        $resto = count($cwes) - TG_CWE_VISIBLES;
        // El separador de las CWE, igual que el del resto del mensaje.
        $identidad[] = '<b>CWE:</b> ' . implode(' · ', $enlazadas) . ($resto > 0 ? ' +' . $resto : '');
    }

    // Los dos subíndices, cada uno en su línea y contra su tope. Separan dos cosas
    // que el score junta: lo fácil que es llegar y lo que se lleva por delante, y
    // en dos líneas se leen en diagonal igual que el resto de los datos.
    $topes = TG_CVSS_TOPES[(string) ($nvd['cvss'] ?? '')] ?? null;
    if ($topes !== null) {
        if (($nvd['explotabilidad'] ?? null) !== null) {
            $medidas[] = '<b>Exploitability:</b> ' . number_format((float) $nvd['explotabilidad'], 1, '.', '')
                . ' / ' . number_format($topes['explotabilidad'], 1, '.', '');
        }
        if (($nvd['impacto'] ?? null) !== null) {
            $medidas[] = '<b>Impact:</b> ' . number_format((float) $nvd['impacto'], 1, '.', '')
                . ' / ' . number_format($topes['impacto'], 1, '.', '');
        }
    }

    // Con hora y diciendo que es UTC: el NVD la publica sin marca horaria, y una
    // fecha a secas hace pensar que la vulnerabilidad lleva un día entero fuera
    // cuando puede llevar veinte minutos.
    if (is_string($nvd['publicado'] ?? null)) {
        $dia  = substr($nvd['publicado'], 0, 10);
        $hora = substr($nvd['publicado'], 11, 5);
        $fechas[] = '<b>Published:</b> ' . $dia
            . (preg_match('/^\d{2}:\d{2}$/', $hora) === 1 ? ' ' . $hora . ' UTC' : '');
    }
    // El plazo de CISA, que el catálogo de VulnCheck arrastra. Va con su nombre
    // porque no es una recomendación de nadie más: es la fecha límite que la BOD de
    // CISA pone a los organismos federales, y en una lista de cosas que ya se están
    // explotando es el único dato con una fecha de verdad.
    if (is_string($vc['plazo'] ?? null)) {
        $fechas[] = '<b>CISA action due:</b> ' . $vc['plazo'];
    }

    $bloques = [];
    foreach ([$identidad, $medidas, $fechas] as $bloque) {
        if (count($bloque) > 0) $bloques[] = implode("\n", $bloque);
    }
    if (count($bloques) > 0) {
        $lineas[] = '';
        $lineas[] = implode("\n\n", $bloques);
    }

    // Lo que el catálogo dice que hay que hacer. Va después de los datos y antes de
    // los enlaces porque es la conclusión del mensaje: lo de arriba explica por qué
    // corre prisa y esto dice qué se hace con ello.
    $accion = trim(preg_replace('/\s+/', ' ', (string) ($vc['accion'] ?? '')));
    if ($accion !== '') {
        if (mb_strlen($accion) > TG_ACCION_MAX) {
            $accion = preg_replace('/\s+\S*$/u', '', mb_substr($accion, 0, TG_ACCION_MAX)) . '…';
        }
        // En una cita como la descripción, y por el mismo motivo: casi siempre es
        // plantilla de CISA, así que ocupa media pantalla diciendo lo de siempre. El
        // rótulo va fuera y encima: dentro de la cita se pliega con el texto y queda un
        // recuadro gris sin decir de qué es.
        $cita = mb_strlen($accion) > TG_DESC_PLEGABLE ? 'blockquote expandable' : 'blockquote';
        $lineas[] = '';
        $lineas[] = "\u{1F6E0}\u{FE0F} <b>Required action</b>";
        $lineas[] = '<' . $cita . '>' . escapar_html($accion) . '</blockquote>';
    }

    // La línea de abajo son las referencias de VulnCheck y nada más. Ni la ficha de
    // la EUVD (iba primera por ser de donde salía el CVSS, y el CVSS ya no sale de
    // ahí) ni el registro del CVE: el identificador está arriba en monoespaciada,
    // que es lo que se copia, y lo que se abre desde el mensaje es lo que justifica
    // el aviso. El "+n" dice cuántas más hay, igual que en las CWE.
    $evidencias = is_array($vc['evidencias'] ?? null) ? $vc['evidencias'] : [];
    if (count($evidencias) > 0) {
        // Cada una se etiqueta con su dominio, que es lo que decide si merece el
        // toque: no es lo mismo el aviso de msrc.microsoft.com que un hilo de x.com.
        // Y por eso se escogen de dominios distintos (dos "x.com" seguidos no dicen
        // nada), aunque el "+n" siga contando todas las que no caben.
        $vistos   = [];
        $elegidas = [];
        foreach ($evidencias as $url) {
            $dominio = dominio_de($url);
            if ($dominio === null || isset($vistos[$dominio])) continue;

            $vistos[$dominio] = true;
            $elegidas[] = ['url' => $url, 'dominio' => $dominio];
            if (count($elegidas) === TG_EVIDENCIAS_VISIBLES) break;
        }

        if (count($elegidas) > 0) {
            $enlaces = [];
            foreach ($elegidas as $e) {
                $enlaces[] = '<a href="' . escapar_html($e['url']) . '">'
                    . escapar_html($e['dominio']) . '</a>';
            }
            $resto = count($evidencias) - count($elegidas);
            // Con su emoji, como los demás bloques: una línea de enlaces suelta al
            // final parece que se ha caído del mensaje en vez de cerrarlo.
            $lineas[] = '';
            $lineas[] = "\u{1F517} " . implode(' · ', $enlaces) . ($resto > 0 ? ' +' . $resto : '');
        }
    }

    if ($actualizado !== null) {
        $lineas[] = '';
        $lineas[] = '<i>Updated ' . str_replace('T', ' ', substr($actualizado, 0, 16)) . ' UTC</i>';
    }

    return implode("\n", $lineas);
}

/**
 * Una sola puerta a la API. Envíos, ediciones y borrados cuentan todos contra el
 * mismo límite del grupo, así que conviene tratarlos igual y devolver siempre la
 * espera que pida un 429 y el motivo, que es lo que distingue un fallo de verdad
 * de un "ese mensaje ya no existe".
 *
 * @param array<string,mixed> $cuerpo
 * @return array{ok: bool, esperar: int, resultado: mixed, motivo: string}
 */
function telegram_llamar(string $token, string $metodo, array $cuerpo): array
{
    $ch = curl_init(TG_API . $token . '/' . $metodo);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_TIMEOUT        => TIMEOUT,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_USERAGENT      => 'euvd-feed/1.0',
        CURLOPT_POSTFIELDS     => json_encode($cuerpo, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    ]);

    $respuesta = curl_exec($ch);
    $codigo    = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error     = curl_error($ch);
    curl_close($ch);

    if ($respuesta === false) {
        log_linea("Telegram: {$metodo} falló: {$error}");
        return ['ok' => false, 'esperar' => 0, 'resultado' => null, 'motivo' => $error];
    }

    $json = json_decode((string) $respuesta, true);
    if ($codigo === 200 && ($json['ok'] ?? false) === true) {
        return ['ok' => true, 'esperar' => 0, 'resultado' => $json['result'] ?? null, 'motivo' => ''];
    }

    $motivo = (string) ($json['description'] ?? "HTTP {$codigo}");
    log_linea("Telegram: {$metodo} falló — {$motivo}");

    return [
        'ok'        => false,
        'esperar'   => (int) ($json['parameters']['retry_after'] ?? 0),
        'resultado' => null,
        'motivo'    => $motivo,
    ];
}

/**
 * Devuelve dónde quedó el mensaje —chat e identificador— porque sin eso no se
 * puede ni editar ni borrar después, y cuánto esperar si Telegram corta (429).
 *
 * @return array{enviado: bool, esperar: int, chat: string, mensaje: int|null}
 */
function telegram_enviar(string $token, string $destino, string $texto): array
{
    ['chat' => $chat, 'hilo' => $hilo] = partir_destino($destino);

    $cuerpo = [
        'chat_id'                  => $chat,
        'text'                     => $texto,
        'parse_mode'               => 'HTML',
        'disable_web_page_preview' => true,
    ];
    if ($hilo !== null) {
        $cuerpo['message_thread_id'] = $hilo;
    }

    $r       = telegram_llamar($token, 'sendMessage', $cuerpo);
    $mensaje = $r['resultado']['message_id'] ?? null;

    return [
        'enviado' => $r['ok'],
        'esperar' => $r['esperar'],
        'chat'    => $chat,
        'mensaje' => $mensaje === null ? null : (int) $mensaje,
    ];
}

/**
 * Pone al día un mensaje sin sacarlo de su tema y sin notificar a nadie: es lo
 * que se quiere cuando una CVE cambia pero se queda en la misma sala.
 *
 * "message is not modified" cuenta como hecha —el texto ya es el que toca, y
 * reintentarlo cada pasada sería pelearse con Telegram para siempre—, y "not
 * found" también, porque es un mensaje borrado a mano: quien llama se entera por
 * `perdido` y tira el identificador en vez de reintentar eternamente.
 *
 * @return array{hecha: bool, esperar: int, perdido: bool}
 */
function telegram_editar(string $token, string $chat, int $mensaje, string $texto): array
{
    $r = telegram_llamar($token, 'editMessageText', [
        'chat_id'                  => $chat,
        'message_id'               => $mensaje,
        'text'                     => $texto,
        'parse_mode'               => 'HTML',
        'disable_web_page_preview' => true,
    ]);

    if ($r['ok'] || stripos($r['motivo'], 'not modified') !== false) {
        return ['hecha' => true, 'esperar' => 0, 'perdido' => false];
    }

    $perdido = stripos($r['motivo'], 'not found') !== false;

    return ['hecha' => $perdido, 'esperar' => $r['esperar'], 'perdido' => $perdido];
}

/**
 * Borra el mensaje de la sala que ha dejado de corresponder. El bot es
 * administrador del grupo con permiso de borrado, así que no le aplica el tope de
 * 48 horas de los mensajes normales: dentro de la ventana de 14 días se puede
 * borrar cualquiera. Si algún día se le quita el permiso, esto empieza a fallar y
 * los mensajes viejos se quedan donde están; se ve en el log.
 *
 * @return array{hecho: bool, esperar: int}
 */
function telegram_borrar(string $token, string $chat, int $mensaje): array
{
    $r = telegram_llamar($token, 'deleteMessage', ['chat_id' => $chat, 'message_id' => $mensaje]);

    if ($r['ok'] || stripos($r['motivo'], 'not found') !== false) {
        return ['hecho' => true, 'esperar' => 0];
    }

    return ['hecho' => false, 'esperar' => $r['esperar']];
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
 *     en él. Ver es_noticia().
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
 * Se llama después de escribir el JSON a propósito: que Telegram no conteste no
 * puede dejar la web sin actualizar.
 *
 * @param array<int,array<string,mixed>> $filas
 * @param array<string,string>           $salas
 */
function notificar_telegram(array $filas, string $token, array $salas, string $respaldo, float $umbral, string $estado_ruta, ?string $registro_sembrado = null, ?array $vulncheck = null): void
{
    $configuradas = count(array_filter($salas));

    if ($token === '' || ($respaldo === '' && $configuradas === 0)) {
        log_linea('Telegram: sin TELEGRAM_BOT_TOKEN o sin ningún chat configurado, no aviso.');
        return;
    }

    // Sin el catálogo de VulnCheck no se puede decidir qué avisar, así que no se
    // avisa: la pasada se va sin tocar Telegram y sin escribir el estado. Escribirlo
    // sería peor que no hacer nada: lo de hoy quedaría anotado como visto y su
    // aviso se perdería para siempre. En diez minutos hay otra pasada.
    if ($vulncheck === null) {
        log_linea('Telegram: sin catálogo de VulnCheck no sé qué avisar; esta pasada no toco nada.');
        return;
    }

    $estado  = leer_cache($estado_ruta);
    $previas = is_array($estado['avisadas'] ?? null) ? $estado['avisadas'] : [];

    // El formato viejo guardaba `euvd: fecha` en vez de `euvd: {sala, fecha}`. Se
    // reconstruye entero y sin avisar, como una siembra: reaprovecharlo mandaría un
    // reaviso por cada fila que antes no tenía sala anotada.
    //
    // Las entradas sin `mensaje` —las escritas antes de que se guardara el
    // identificador— no son ni editables ni movibles, pero eso no rompe nada: se
    // les anota la firma, siguen contando para no reavisar, y en 14 días salen de la
    // ventana solas.
    $formato_viejo = false;
    foreach ($previas as $entrada) {
        if (!is_array($entrada)) {
            $formato_viejo = true;
            break;
        }
    }
    $primera_vez = !is_string($estado['sembrado'] ?? null);

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
    $kev_sin_sembrar = !is_string($estado['sembradoKev'] ?? null) && $registro_sembrado === null;

    // El marcador solo se pone si el catálogo llegó de verdad. Si la petición falló,
    // $filas no trae nada de fuera de ventana y darla por sembrada dejaría el
    // volcado para la pasada siguiente, que es justo lo que se quiere evitar.
    $hay_fuera_de_ventana = false;
    foreach ($filas as $fila) {
        if (($fila['fueraDeVentana'] ?? false) === true) {
            $hay_fuera_de_ventana = true;
            break;
        }
    }

    $ahora = gmdate('c');

    // La poda: lo que sigue apareciendo se marca visto, y lo que lleva
    // TG_OLVIDO_DIAS sin aparecer se olvida, para que el fichero no crezca sin fin.
    //
    // Lo que no vale es quedarse solo con lo que trae esta pasada. $filas no es la
    // ventana, es lo que se ha podido descargar de la ventana: una página que falla
    // o un catálogo de KEV que no baja se lleva por delante cientos de apuntes, y
    // sin apunte esas filas vuelven a contar como no avisadas en la pasada
    // siguiente. Así es como acaban en la sala de KEV CVE de hace años.
    $presentes = [];
    foreach ($filas as $fila) {
        $presentes[$fila['euvd']] = true;
    }

    $olvidar  = strtotime($ahora) - TG_OLVIDO_DIAS * 86400;
    $vigentes = [];
    foreach ($previas as $euvd => $previa) {
        if (isset($presentes[$euvd])) {
            if (is_array($previa)) {
                $previa['visto'] = $ahora;
            }
            $vigentes[$euvd] = $previa;
            continue;
        }

        // Sin fecha que mirar —las entradas del formato viejo son una cadena— se deja
        // caer: ese formato lo reconstruye entero el bloque de siembra de más abajo.
        $visto = is_array($previa) ? ($previa['visto'] ?? $previa['fecha'] ?? null) : null;
        $t = is_string($visto) ? strtotime($visto) : false;
        if ($t !== false && $t >= $olvidar) {
            $vigentes[$euvd] = $previa;
        }
    }

    // Igual que en el .mjs: si no hay marcador y tampoco hay nada sembrado, la
    // clave se omite y el marcador queda para la pasada que sí traiga catálogo.
    $marca_kev = is_string($estado['sembradoKev'] ?? null)
        ? $estado['sembradoKev']
        : ($hay_fuera_de_ventana ? $ahora : null);
    $estado_base = ['sembradoKev' => $marca_kev];
    if ($marca_kev === null) {
        unset($estado_base['sembradoKev']);
    }

    // La pausa va antes que nada: ni siembra, ni avisos, ni ediciones. Lo que hay
    // se anota como visto y ahí se queda. Si una fila ya tenía mensaje publicado se
    // conserva su apunte tal cual —identificador y sala incluidos— para que al
    // reanudar se pueda seguir editando y moviendo en vez de duplicarla.
    if (TG_EN_PAUSA) {
        foreach ($filas as $fila) {
            $sala  = sala_de($fila);
            $previa = $vigentes[$fila['euvd']] ?? null;
            $firma = firma_fila($fila, $sala, ficha_de($fila, $vulncheck));
            $vigentes[$fila['euvd']] = is_array($previa)
                ? array_merge($previa, ['visto' => $ahora, 'firma' => $firma])
                : [
                    'sala'    => $sala,
                    'fecha'   => $ahora,
                    'visto'   => $ahora,
                    'enviada' => false,
                    'firma'   => $firma,
                ];
        }
        escribir_json($estado_ruta, $estado_base + [
            'sembrado' => is_string($estado['sembrado'] ?? null) ? $estado['sembrado'] : $ahora,
            'avisadas' => $vigentes,
        ]);
        log_linea('Telegram: en pausa (TELEGRAM_PAUSA). Anotadas ' . count($filas)
            . ' vulnerabilidades sin avisar; quita la pausa para que vuelvan a salir avisos de lo '
            . 'que aparezca a partir de entonces.');
        return;
    }

    if ($primera_vez || $formato_viejo) {
        foreach ($filas as $fila) {
            $sala = sala_de($fila);
            $vigentes[$fila['euvd']] = [
                'sala'    => $sala,
                'fecha'   => $ahora,
                'visto'   => $ahora,
                'enviada' => false,
                'firma'   => firma_fila($fila, $sala, ficha_de($fila, $vulncheck)),
            ];
        }
        escribir_json($estado_ruta, $estado_base + [
            'sembrado' => is_string($estado['sembrado'] ?? null) ? $estado['sembrado'] : $ahora,
            'avisadas' => $vigentes,
        ]);
        log_linea('Telegram: ' . ($primera_vez ? 'primera ejecución' : 'estado en formato antiguo')
            . ', siembro ' . count($filas) . ' vulnerabilidades sin avisar. A partir de la siguiente '
            . 'pasada solo llega lo nuevo.');
        return;
    }

    $envios    = [];  // primer aviso y mudanzas: los dos acaban en un sendMessage
    $ediciones = [];  // misma sala, contenido distinto

    foreach ($filas as $fila) {
        $sala    = sala_de($fila);
        $previa  = $vigentes[$fila['euvd']] ?? null;
        $vc      = ficha_de($fila, $vulncheck);
        $firma   = firma_fila($fila, $sala, $vc);
        $destino = destino_de($sala, $fila, $salas, $respaldo, $umbral);

        // El filtro: lo que VulnCheck no da por explotado se anota y ahí se queda.
        // No se envía, no se edita y no se mueve de sala.
        //
        // Tampoco se borra lo que se publicó antes de poner el filtro: esos mensajes
        // se quedan donde están y su apunte se cae solo en TG_OLVIDO_DIAS. Borrarlos
        // sería un barrido de cientos de mensajes que nadie ha pedido, y el grupo
        // queda limpio igual en dos semanas sin tocar nada.
        if (!es_vulncheck_kev($fila)) {
            $vigentes[$fila['euvd']] = is_array($previa)
                ? array_merge($previa, ['visto' => $ahora, 'firma' => $firma])
                : ['sala' => $sala, 'fecha' => $ahora, 'visto' => $ahora,
                   'enviada' => false, 'firma' => $firma];
            continue;
        }

        // La siembra del catálogo: solo la primera vez y solo lo que entra por él.
        // Lo que ya estaba anotado sigue su camino normal, incluidas las ediciones.
        if ($kev_sin_sembrar && ($fila['fueraDeVentana'] ?? false) === true && $previa === null) {
            $vigentes[$fila['euvd']] = [
                'sala' => $sala, 'fecha' => $ahora, 'visto' => $ahora,
                'enviada' => false, 'firma' => $firma,
            ];
            continue;
        }

        // Primer aviso de algo que ya no es noticia: se anota callado, como la
        // siembra. Es la red que hace que el estado no sea lo único que separa la sala
        // de KEV de un volcado del catálogo: aunque el fichero se pierda entero, de
        // fuera de la ventana solo se avisa lo que acaba de entrar en KEV.
        if ($previa === null && !es_noticia($fila, $ahora)) {
            $vigentes[$fila['euvd']] = [
                'sala' => $sala, 'fecha' => $ahora, 'visto' => $ahora,
                'enviada' => false, 'firma' => $firma,
            ];
            continue;
        }

        // Ya anotada y sigue en su sala: como mucho, una edición silenciosa.
        if ($previa !== null && (string) ($previa['sala'] ?? '') === $sala) {
            if (($previa['firma'] ?? null) === $firma) {
                continue;
            }
            if (($previa['enviada'] ?? false) && ($previa['mensaje'] ?? null) !== null) {
                $ediciones[] = ['fila' => $fila, 'sala' => $sala, 'previa' => $previa, 'firma' => $firma, 'vc' => $vc];
            } else {
                $previa['firma'] = $firma;
                $vigentes[$fila['euvd']] = $previa;
            }
            continue;
        }

        // Sin sala montada: se anota y no se vuelve a mirar mientras no cambie de
        // sala. Si venía publicada de otra, se borra: allí ya no pinta nada.
        if ($destino === '') {
            if (($previa['mensaje'] ?? null) !== null) {
                $envios[] = [
                    'fila' => $fila, 'sala' => $sala, 'destino' => '',
                    'previa' => $previa, 'firma' => $firma, 'vc' => $vc, 'solo_borrar' => true,
                ];
            } else {
                $vigentes[$fila['euvd']] = [
                    'sala' => $sala, 'fecha' => $ahora, 'visto' => $ahora,
                    'enviada' => false, 'firma' => $firma,
                ];
            }
            continue;
        }

        $envios[] = [
            'fila' => $fila, 'sala' => $sala, 'destino' => $destino,
            'previa' => $previa, 'firma' => $firma, 'vc' => $vc, 'solo_borrar' => false,
        ];
    }

    if (count($envios) === 0 && count($ediciones) === 0) {
        log_linea('Telegram: nada nuevo que avisar ni que actualizar.');
        escribir_json($estado_ruta, $estado_base + ['sembrado' => $estado['sembrado'], 'avisadas' => $vigentes]);
        return;
    }

    // Por sala y luego por puntuación: si un día hay atasco, lo que ya se está
    // explotando sale delante.
    usort($envios, static function (array $a, array $b): int {
        return (prioridad_sala($b['sala']) <=> prioridad_sala($a['sala']))
            ?: ((float) ($b['fila']['score'] ?? 0) <=> (float) ($a['fila']['score'] ?? 0));
    });

    // Envíos, ediciones y borrados van todos contra el mismo límite del grupo, así
    // que la pausa la lleva un único contador y no cada bucle por su cuenta.
    $llamadas = 0;
    $ritmo = static function () use (&$llamadas): void {
        if ($llamadas > 0) {
            usleep(TG_PAUSA_US);
        }
        $llamadas++;
    };

    $enviadas = [];
    $total    = 0;
    $hechos   = 0;
    $mudadas  = 0;
    $editadas = 0;
    $cortado  = false;

    foreach ($envios as $e) {
        // El tope es por sala: el límite de Telegram es por chat, así que un atasco en
        // medias no tiene por qué retrasar el aviso de una crítica.
        $cupo = ($enviadas[$e['sala']] ?? 0) + 1;
        if (!$e['solo_borrar'] && $cupo > TG_MAX_MENSAJES) {
            continue;  // sin marcar: sale en la siguiente pasada
        }

        $previa = $e['previa'];
        $apunte = [
            'sala' => $e['sala'], 'fecha' => $ahora, 'visto' => $ahora,
            'enviada' => false, 'firma' => $e['firma'],
        ];

        if (!$e['solo_borrar']) {
            // El encabezado de mudanza solo tiene sentido si de la anterior se llegó a
            // avisar; si no, para quien lo lee es un mensaje nuevo y punto.
            $ritmo();
            // La puntuación se pide aquí y no antes: solo hace falta para lo que de
            // verdad se manda, que con el filtro puesto son unos pocos por pasada.
            $texto = mensaje_telegram(
                $e['fila'],
                $e['vc'] ?? null,
                datos_vulncheck_nvd($e['fila']['cve'] ?? null),
                ($previa !== null && ($previa['enviada'] ?? false)) ? $previa : null
            );
            $r = telegram_enviar($token, $e['destino'], $texto);

            if (!$r['enviado']) {
                // 429: Telegram dice cuánto callar. Cortamos y lo retomamos en la pasada
                // siguiente; lo no enviado se queda sin marcar, así que no se pierde.
                if ($r['esperar'] > 0) {
                    log_linea('Telegram: me pide esperar ' . $r['esperar']
                        . ' s; lo dejo para la siguiente pasada.');
                    $cortado = true;
                    break;
                }
                continue;  // sin marcar: se reintenta en la siguiente pasada
            }

            $apunte = [
                'sala'    => $e['sala'],
                'fecha'   => $ahora,
                'visto'   => $ahora,
                'enviada' => true,
                'chat'    => $r['chat'],
                'mensaje' => $r['mensaje'],
                'firma'   => $e['firma'],
            ];
            $enviadas[$e['sala']] = $cupo;
            $total++;
        }

        // Y ahora el viejo, que ya no corresponde a esta sala. Va después del envío a
        // propósito: si falla el borrado queda un duplicado, pero si fallara al revés
        // nos quedaríamos sin aviso.
        if (($previa['mensaje'] ?? null) !== null && ($previa['chat'] ?? '') !== '') {
            $ritmo();
            $b = telegram_borrar($token, (string) $previa['chat'], (int) $previa['mensaje']);
            if ($b['hecho']) {
                $mudadas++;
            } else {
                log_linea('Telegram: no pude borrar el mensaje de ' . $e['fila']['euvd']
                    . ' en la sala ' . (string) ($previa['sala'] ?? '?') . '.');
            }
        }

        $vigentes[$e['fila']['euvd']] = $apunte;
        $hechos++;
    }

    // Las ediciones, al final: no notifican a nadie, así que si la pasada se queda
    // sin tiempo o sin cupo, lo justo es que cedan el turno a los avisos.
    if (!$cortado) {
        foreach ($ediciones as $ed) {
            if ($editadas >= TG_MAX_EDICIONES) {
                break;  // el resto, en la siguiente pasada
            }

            $previa = $ed['previa'];
            $ritmo();
            $r = telegram_editar(
                $token,
                (string) $previa['chat'],
                (int) $previa['mensaje'],
                mensaje_telegram($ed['fila'], $ed['vc'] ?? null,
                    datos_vulncheck_nvd($ed['fila']['cve'] ?? null), null, $ahora)
            );

            if (!$r['hecha']) {
                if ($r['esperar'] > 0) {
                    log_linea('Telegram: me pide esperar ' . $r['esperar']
                        . ' s; dejo las ediciones para la siguiente pasada.');
                    $cortado = true;
                    break;
                }
                continue;
            }

            // Si el mensaje ya no existe se olvida el identificador y la fila vuelve a
            // contar como anotada pero no publicada: no se reenvía —eso sería avisar dos
            // veces de lo mismo— pero tampoco se reintenta editar cada pasada.
            if ($r['perdido']) {
                $vigentes[$ed['fila']['euvd']] = [
                    'sala'    => $ed['sala'],
                    'fecha'   => $previa['fecha'],
                    'visto'   => $ahora,
                    'enviada' => false,
                    'firma'   => $ed['firma'],
                ];
            } else {
                $previa['firma'] = $ed['firma'];
                $vigentes[$ed['fila']['euvd']] = $previa;
            }
            $editadas++;
        }
    }

    escribir_json($estado_ruta, $estado_base + ['sembrado' => $estado['sembrado'], 'avisadas' => $vigentes]);

    $desglose = [];
    foreach ($enviadas as $sala => $n) {
        $desglose[] = $sala . ' ' . $n;
    }
    $cola = (count($envios) - $hechos) + (count($ediciones) - $editadas);

    log_linea('Telegram: ' . $total . ' avisos enviados'
        . (count($desglose) > 0 ? ' (' . implode(', ', $desglose) . ')' : '')
        . ($mudadas > 0 ? ', ' . $mudadas . ' movidos de sala' : '')
        . ($editadas > 0 ? ', ' . $editadas . ' actualizados en el sitio' : '')
        . ($cola > 0 ? ', ' . $cola . ' para la siguiente pasada' . ($cortado ? ' (me cortaron)' : '') : ''));
}

// ---------------------------------------------------------------- corte

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
function filtrar_nuevas(array $filas, string $registro_ruta): array
{
    $estado    = leer_cache($registro_ruta);
    $conocidas = is_array($estado['ids'] ?? null) ? $estado['ids'] : [];
    $primera_revision = !is_string($estado['sembrado'] ?? null);

    $ahora_iso = gmdate('c');
    $ahora     = time();
    $caduca    = VENTANA_DIAS * 86400;
    $olvido    = VISTAS_OLVIDO_DIAS * 86400;
    // Lo anotado en la primera revisión lleva su misma marca de tiempo, y no se
    // publica nunca: es justo el fondo del que se quería vaciar el feed. Solo sube
    // a la web lo que se haya visto por primera vez después de ese momento.
    $sembrado_t = strtotime(is_string($estado['sembrado'] ?? null) ? $estado['sembrado'] : $ahora_iso);

    $vigentes    = [];
    $publicables = [];
    $caducadas   = 0;
    $nuevas      = 0;

    foreach ($filas as $fila) {
        $previa  = $conocidas[$fila['euvd']] ?? null;
        $primera = is_array($previa) && is_string($previa['p'] ?? null) ? $previa['p'] : null;

        if ($primera === null) {
            $vigentes[$fila['euvd']] = ['p' => $ahora_iso, 'v' => $ahora_iso];
            if (!$primera_revision) {
                $publicables[] = $fila;
                $nuevas++;
            }
            continue;
        }

        // Se conserva la fecha del primer avistamiento: es la que manda la caducidad,
        // no la de publicación. Una ficha que la EUVD publica con fecha de hace tres
        // días entra hoy y se queda sus 14 días completos, que es lo útil.
        $vigentes[$fila['euvd']] = ['p' => $primera, 'v' => $ahora_iso];
        $desde = strtotime($primera);
        if ($desde === false || $desde <= $sembrado_t) {
            continue;  // del fondo inicial: ni se publica ni caduca
        }
        if ($ahora - $desde <= $caduca) {
            $publicables[] = $fila;
        } else {
            $caducadas++;
        }
    }

    // Lo que no ha venido en esta pasada sigue en el registro mientras no lleve
    // demasiado sin verse. Si se olvidara antes de que la EUVD deje de devolverlo,
    // la pasada siguiente lo tomaría por nuevo: así es como una descarga corta se
    // convierte en una avalancha de avisos de cosas de hace dos semanas.
    foreach ($conocidas as $euvd => $entrada) {
        if (isset($vigentes[$euvd])) {
            continue;
        }
        $cuando = is_array($entrada) ? ($entrada['v'] ?? $entrada['p'] ?? null) : null;
        $visto  = is_string($cuando) ? strtotime($cuando) : false;
        if ($visto !== false && $ahora - $visto <= $olvido) {
            $vigentes[$euvd] = $entrada;
        }
    }

    escribir_json($registro_ruta, [
        'sembrado' => is_string($estado['sembrado'] ?? null) ? $estado['sembrado'] : $ahora_iso,
        'ids'      => $vigentes,
    ]);

    if ($primera_revision) {
        // La última entrada, que es la marca de la que cuelga todo lo demás: lo que
        // llegue por delante de esta es lo que se ingiere en la revisión siguiente.
        $ultima = null;
        foreach ($filas as $fila) {
            if ($ultima === null || strcmp((string) $fila['fecha'], (string) $ultima['fecha']) > 0) {
                $ultima = $fila;
            }
        }
        log_linea('Primera revisión: anotadas ' . count($filas) . ' entradas sin publicar ninguna. '
            . ($ultima !== null
                ? 'La última es ' . $ultima['euvd'] . ' (' . ($ultima['cve'] ?? 'sin CVE') . '), del '
                    . $ultima['fecha'] . '. '
                : '')
            . 'A partir de la pasada siguiente solo entra lo que no esté en esta lista.');
        return [];
    }

    log_linea('Registro: ' . count($publicables) . ' filas en el feed (' . $nuevas
        . ' nuevas en esta pasada, ' . $caducadas . ' retiradas por pasar de ' . VENTANA_DIAS
        . ' días, ' . count($vigentes) . ' conocidas en total)');

    return $publicables;
}

// ---------------------------------------------------------------- cerrojo

// Un solo sync a la vez. Con el cron cada 15 minutos y pasadas completas de tres
// minutos, dos procesos solapados se pisarían las cachés y el rename atómico.
// flock lo suelta el sistema al morir el proceso, así que no hay cerrojos
// zombis; $cerrojo se queda en ámbito global a propósito, para que el candado
// dure lo que dure la ejecución.
$cerrojo = fopen($cerrojo_ruta, 'c');

if ($cerrojo === false || !flock($cerrojo, LOCK_EX | LOCK_NB)) {
    log_linea('Ya hay otro sync en marcha; no hago nada.');
    exit(0);
}

log_linea($rapido ? 'Pasada rápida (NVD y EPSS desde caché)' : 'Pasada completa');

// ---------------------------------------------------------------- descarga

$desde = gmdate('Y-m-d', strtotime('-' . VENTANA_DIAS . ' days'));
$hasta = gmdate('Y-m-d');

$registros = [];
$total_api = null;

for ($pagina = 0; $pagina < MAX_PAGINAS; $pagina++) {
    $url = API_SEARCH . '?' . http_build_query([
        'fromDate'  => $desde,
        'toDate'    => $hasta,
        'fromScore' => 0,
        'toScore'   => 10,
        'page'      => $pagina,
        'size'      => PAGE_SIZE,
    ]);

    $respuesta = pedir($url);
    if ($respuesta === null) {
        log_linea("Página {$pagina} falló; corto aquí y conservo lo descargado.");
        break;
    }

    $total_api = $respuesta['total'] ?? $total_api;
    $items     = $respuesta['items'] ?? [];

    if (!is_array($items) || count($items) === 0) {
        break;
    }

    foreach ($items as $item) {
        $fila = normalizar($item);
        if ($fila !== null) {
            $registros[$fila['euvd']] = $fila;  // la clave deduplica
        }
    }

    log_linea('Página ' . $pagina . ': ' . count($items) . ' items (acumulado: ' . count($registros)
        . ($total_api ? ' de ' . $total_api : '') . ')');

    if (count($items) < PAGE_SIZE) {
        break;
    }
    if ($total_api && count($registros) >= (int) $total_api) {
        break;
    }
    usleep(PAUSA_US);
}

if (count($registros) === 0) {
    log_linea('Sin registros. No sobrescribo el JSON anterior.');
    exit(1);
}

// Aviso claro si el tope se queda corto: es la diferencia entre "esto es todo" y
// "esto es lo que cupo".
if ($total_api && count($registros) < (int) $total_api) {
    log_linea('AVISO: la EUVD dice ' . $total_api . ' en la ventana y solo tengo ' . count($registros)
        . '. Sube MAX_PAGINAS o acorta VENTANA_DIAS.');
}

// ---------------------------------------------------------------- salida

// El catálogo va antes de construir las filas, para que lo que siembre pase por
// los mismos enriquecidos que lo demás: título de cve.org, CWE y EPSS. Las CWE
// del NVD sí se las pierde (esas se piden por ventana de publicación), pero la
// fuente principal de CWE es cve.org y el NVD solo es el respaldo.
$entradas_kev  = pedir_kev();
$vulncheck_kev = pedir_vulncheck_kev();
sembrar_kev($registros, $entradas_kev, $cache_kev, $vulncheck_kev);

$filas = array_values($registros);

usort($filas, static function (array $a, array $b): int {
    return strcmp((string) $b['fecha'], (string) $a['fecha']);  // más recientes primero
});

completar_meta($filas, $cache_meta);
completar_cwes_nvd($filas, $cache_cwes, $nvd_clave, $nvd_pausa_us, $rapido);
completar_epss($filas, $cache_epss, $rapido);
completar_kev($filas, $entradas_kev, $vulncheck_kev);

// Se filtra al final, con las filas ya enriquecidas y en un solo sitio: lo que
// salga de aquí es lo que se publica y lo único de lo que Telegram llega a
// enterarse. Las dos cosas son la misma lista a propósito.
$publicables = filtrar_nuevas($filas, $registro_vistas);
$registro    = leer_cache($registro_vistas);

$salida = [
    'generado'      => gmdate('c'),
    'ventanaDias'   => VENTANA_DIAS,
    // Cuándo se hizo la primera revisión y cuánto lleva visto el feed.
    'desdeCero'     => $registro['sembrado'] ?? null,
    'conocidas'     => count($registro['ids'] ?? []),
    'modo'          => $rapido ? 'rapido' : 'completo',
    'desde'         => $desde,
    'hasta'         => $hasta,
    'total'         => count($publicables),
    // Lo que la EUVD dice tener en la ventana, sin lo sembrado por KEV.
    'totalEnEuvd'   => $total_api,
    'fueraDeVentana' => count(array_filter(
        $publicables,
        static fn (array $f): bool => ($f['fueraDeVentana'] ?? false) === true
    )),
    'fuente'        => 'EU Vulnerability Database (ENISA)',
    'fuenteScore'   => 'EU Vulnerability Database (ENISA)',
    'fuenteEpss'    => 'EPSS de FIRST',
    'fuenteKev'     => 'VulnCheck KEV, más CISA KEV y EU KEV vía EUVD',
    'fuenteCwe'     => 'cve.org, con el NVD de respaldo',
    'items'         => $publicables,
];

if (!escribir_json($destino, $salida)) {
    exit(1);
}

log_linea('Escritas ' . count($publicables) . ' vulnerabilidades en ' . $destino
    . ' (' . ($rapido ? 'pasada rápida' : 'pasada completa') . ')');

notificar_telegram($publicables, $tg_token, $tg_salas, $tg_chat, $tg_umbral, $estado_telegram,
    $registro['sembrado'] ?? null, $vulncheck_kev);
