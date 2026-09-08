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

// Arranque en frío. Nada anterior a esta marca entra en el feed, aunque la EUVD
// lo siga devolviendo dentro de la ventana. Existe para poder vaciar el feed y
// empezar de cero: sin ella, la pasada siguiente al borrado lo rellena otra vez
// con los 14 días de historia que la API sigue trayendo, y Telegram los toma por
// novedades. Es temporal por naturaleza: a los VENTANA_DIAS días la ventana ya no
// alcanza al corte y deja de descartar nada, así que se puede quitar y todo sigue
// igual. Vacía —lo normal— significa sin corte.
//
// El precio, y solo durante esos 14 días: una vulnerabilidad que la EUVD publique
// con fecha anterior al corte no aparece. Se prefiere eso a la avalancha.
define('SYNC_CORTE', getenv('SYNC_DESDE') ?: '');

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
 */
function sembrar_kev(array &$registros, ?array $entradas, string $cache_ruta): void
{
    if ($entradas === null) {
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

    $faltan = [];
    foreach ($entradas as $e) {
        $euvd = $e['euvdId'] ?? null;
        if (!is_string($euvd) || isset($en_ventana[$euvd])) continue;

        $cve = $e['cveId'] ?? null;
        if (is_string($cve) && isset($en_ventana[$cve])) continue;

        $faltan[] = $euvd;
    }

    $pendientes = [];
    foreach ($faltan as $euvd) {
        if (!isset($cache[$euvd])) $pendientes[] = $euvd;
    }

    log_linea('KEV: ' . count($faltan) . ' explotadas fuera de la ventana, '
        . (count($faltan) - count($pendientes)) . ' en caché, ' . count($pendientes) . ' por pedir');

    $hechas = 0;
    foreach ($pendientes as $euvd) {
        $ficha = pedir(API_ENISAID . '?' . http_build_query(['id' => $euvd]));
        $fila  = is_array($ficha) ? normalizar($ficha) : null;
        // Los fallos no se cachean: se reintentan en la pasada siguiente, igual que
        // en completar_meta(). Una ficha que no baja hoy baja dentro de diez minutos.
        if ($fila !== null) $cache[$euvd] = $fila;
        if (++$hechas % 50 === 0) log_linea('  ' . $hechas . '/' . count($pendientes) . ' fichas de la EUVD');
        usleep(PAUSA_US);
    }

    // Poda: la caché se queda solo con lo que sigue en el catálogo.
    $vigentes = [];
    $sembradas = 0;
    foreach ($faltan as $euvd) {
        $fila = $cache[$euvd] ?? null;
        if (!is_array($fila)) continue;

        $vigentes[$euvd] = $fila;
        // La marca es lo que distingue una fila traída por el catálogo de una traída
        // por la ventana. La usa notificar_telegram() para no vaciar el catálogo
        // entero en la sala de KEV la primera vez, y sale en el JSON porque es una
        // diferencia real: esta fila está aquí por estar explotada, no por reciente.
        $fila['fueraDeVentana'] = true;
        $registros[$euvd] = $fila;
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
 */
function completar_kev(array &$filas, ?array $entradas): void
{
    if ($entradas === null) {
        log_linea('KEV: sin catálogo, las filas se quedan sin marcar.');
        return;
    }

    $por_cve  = [];
    $por_euvd = [];
    foreach ($entradas as $e) {
        if (is_string($e['cveId'] ?? null))  $por_cve[$e['cveId']]   = $e;
        if (is_string($e['euvdId'] ?? null)) $por_euvd[$e['euvdId']] = $e;
    }

    $marcadas = 0;
    foreach ($filas as &$fila) {
        $cve = $fila['cve'];
        $kev = (is_string($cve) ? ($por_cve[$cve] ?? null) : null) ?? ($por_euvd[$fila['euvd']] ?? null);
        if ($kev === null) continue;

        $fuentes = $kev['sources'] ?? [];
        $fila['kev'] = [
            'fecha'   => is_string($kev['dateAdded'] ?? null) ? $kev['dateAdded'] : null,
            'fuentes' => is_array($fuentes) ? array_values($fuentes) : [],
        ];
        $marcadas++;
    }
    unset($fila);

    log_linea($marcadas . ' de ' . count($filas) . ' filas explotadas activamente (KEV tiene '
        . count($entradas) . ')');
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
 * @param array<string,mixed> $fila
 */
function firma_fila(array $fila, string $sala): string
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

/** Los catálogos se identifican con su nombre, no con la clave de la API. */
const TG_FUENTE_KEV = ['cisa_kev' => 'CISA KEV', 'eukev_kev' => 'EU KEV'];

// La descripción va en una cita: por encima de TG_DESC_PLEGABLE, Telegram la
// pliega y deja el resto del mensaje a la vista. El tope duro existe porque hay
// descripciones de 4.000 caracteres y un mensaje entero no puede pasar de 4.096.
const TG_DESC_PLEGABLE = 300;
const TG_DESC_MAX      = 3000;

const TG_CWE_VISIBLES  = 3;  // el mismo tope que la tabla; el resto va como "+n"

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
function mensaje_telegram(array $fila, ?array $previa = null, ?string $actualizado = null): string
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

    $marca      = $marcas[$fila['severidad']] ?? $marcas['sin_puntuar'];
    // El 0 de la EUVD es un hueco, no una puntuación: la cabecera se queda con la
    // marca de "Unscored" a secas, sin un CVSS 0.0 que nadie ha puesto.
    $puntuacion = ($fila['score'] !== null && $fila['score'] > 0.0)
        ? ' · CVSS <b>' . number_format((float) $fila['score'], 1, '.', '') . '</b>'
        : '';
    $lineas[] = $marca . $puntuacion . ' · <code>' . escapar_html($fila['cve'] ?? $fila['euvd']) . '</code>';

    // La descripción trae saltos de línea a media frase, así que se normaliza.
    $descripcion = trim(preg_replace('/\s+/', ' ', (string) ($fila['descripcion'] ?? '')));

    // Cuando cve.org no tiene título, `nombre` es el primer trozo de la propia
    // descripción —una de cada cuatro filas—: repetirlo sería enseñar dos veces la
    // misma frase, así que ahí manda la descripción, que además viene entera.
    $titulo = $fila['nombre'] === 'Sin descripción' ? '' : (string) ($fila['nombre'] ?? '');
    $recorte = trim(preg_replace('/…$/u', '', $titulo));

    if ($titulo !== '' && ($recorte === '' || !str_starts_with($descripcion, $recorte))) {
        $lineas[] = '<b>' . escapar_html($titulo) . '</b>';
    }

    if (is_array($fila['kev'])) {
        $fuentes = [];
        foreach ($fila['kev']['fuentes'] ?? [] as $f) {
            $fuentes[] = TG_FUENTE_KEV[$f] ?? strtoupper((string) $f);
        }
        $desde = is_string($fila['kev']['fecha'] ?? null)
            ? ', added ' . substr($fila['kev']['fecha'], 0, 10)
            : '';
        $lineas[] = '';
        $lineas[] = "\u{26A0}\u{FE0F} <b>Actively exploited</b>"
            . (count($fuentes) > 0 ? ' — ' . escapar_html(implode(' · ', $fuentes)) : '')
            . $desde;
    }

    if ($descripcion !== '') {
        if (mb_strlen($descripcion) > TG_DESC_MAX) {
            $descripcion = preg_replace('/\s+\S*$/u', '', mb_substr($descripcion, 0, TG_DESC_MAX)) . '…';
        }
        $cita = mb_strlen($descripcion) > TG_DESC_PLEGABLE ? 'blockquote expandable' : 'blockquote';
        $lineas[] = '';
        $lineas[] = '<' . $cita . '>' . escapar_html($descripcion) . '</blockquote>';
    }

    // Datos etiquetados: se leen en diagonal y cada uno se calla si no hay dato,
    // que es mejor que una fila con un guion.
    $datos = [];

    if ($fila['vendor'] !== null && $fila['vendor'] !== '') {
        $datos[] = '<b>Vendor:</b> ' . escapar_html($fila['vendor']);
    }
    if ($fila['producto'] !== null && $fila['producto'] !== '' && $fila['producto'] !== $fila['vendor']) {
        $datos[] = '<b>Product:</b> ' . escapar_html($fila['producto']);
    }

    if ($fila['epss'] !== null) {
        $probabilidad = number_format((float) $fila['epss'] * 100, 1, '.', '');
        $percentil    = $fila['epssPercentil'] !== null
            ? ' (percentile ' . round((float) $fila['epssPercentil'] * 100) . ')'
            : '';
        $datos[] = '<b>EPSS:</b> ' . $probabilidad . '%' . $percentil;
    }

    // Enlazadas a cwe.mitre.org, igual que en la tabla, y con el mismo tope de tres
    // visibles y un "+n" con el resto: en un mensaje de móvil, seis identificadores
    // seguidos ocupan más que todo lo demás junto.
    $cwes = array_values(array_filter(
        array_column($fila['cwes'] ?? [], 'id'),
        static fn ($id): bool => is_string($id) && preg_match('/^CWE-\d+$/', $id) === 1
    ));

    if (count($cwes) > 0) {
        $enlazadas = [];
        foreach (array_slice($cwes, 0, TG_CWE_VISIBLES) as $id) {
            $enlazadas[] = '<a href="https://cwe.mitre.org/data/definitions/'
                . substr($id, 4) . '.html">' . $id . '</a>';
        }
        $resto = count($cwes) - TG_CWE_VISIBLES;
        $datos[] = '<b>CWE:</b> ' . implode(', ', $enlazadas) . ($resto > 0 ? ' +' . $resto : '');
    }

    if (is_string($fila['fecha'])) {
        $datos[] = '<b>Published:</b> ' . substr($fila['fecha'], 0, 10);
    }

    if (count($datos) > 0) {
        $lineas[] = '';
        $lineas   = array_merge($lineas, $datos);
    }

    // El primer enlace es la ficha de la EUVD, que es de donde sale el CVSS del
    // mensaje. Antes iba al NVD, y mandar a una ficha que puntuaba otra cosa —o que
    // sigue en "Awaiting Analysis"— era justo lo que hacía dudar del número.
    $enlaces = [
        '<a href="https://euvd.enisa.europa.eu/vulnerability/'
            . escapar_html($fila['euvd']) . '">EUVD</a>',
    ];
    if (is_string($fila['cve'])) {
        $enlaces[] = '<a href="https://www.cve.org/CVERecord?id=' . escapar_html($fila['cve']) . '">CVE Record</a>';
    }
    $lineas[] = '';
    $lineas[] = implode(' · ', $enlaces);

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
function notificar_telegram(array $filas, string $token, array $salas, string $respaldo, float $umbral, string $estado_ruta): void
{
    $configuradas = count(array_filter($salas));

    if ($token === '' || ($respaldo === '' && $configuradas === 0)) {
        log_linea('Telegram: sin TELEGRAM_BOT_TOKEN o sin ningún chat configurado, no aviso.');
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
    $kev_sin_sembrar = !is_string($estado['sembradoKev'] ?? null);

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
            $firma = firma_fila($fila, $sala);
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
                'firma'   => firma_fila($fila, $sala),
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
        $firma   = firma_fila($fila, $sala);
        $destino = destino_de($sala, $fila, $salas, $respaldo, $umbral);

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
                $ediciones[] = ['fila' => $fila, 'sala' => $sala, 'previa' => $previa, 'firma' => $firma];
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
                    'previa' => $previa, 'firma' => $firma, 'solo_borrar' => true,
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
            'previa' => $previa, 'firma' => $firma, 'solo_borrar' => false,
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
            $texto = mensaje_telegram(
                $e['fila'],
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
                mensaje_telegram($ed['fila'], null, $ahora)
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
 * Deja fuera del feed lo que no toca publicar: lo anterior al corte y lo que ya
 * ha cumplido sus VENTANA_DIAS. Se aplica al final, sobre las filas ya
 * enriquecidas, y lo que descarta no llega ni a la web ni a Telegram: son la
 * misma lista.
 */
function aplicar_corte(array $filas): array
{
    if (SYNC_CORTE === '') {
        return $filas;
    }

    $corte = strtotime(SYNC_CORTE);
    if ($corte === false) {
        log_linea('AVISO: SYNC_DESDE no es una fecha ISO (' . SYNC_CORTE . '); publico la ventana entera.');
        return $filas;
    }

    // El catálogo de KEV fecha por días, no por horas: lo que entró hoy viene
    // marcado a medianoche y quedaría por detrás de un corte puesto a media tarde.
    // Para esas filas el corte es el día, no el instante.
    $corte_dia  = strtotime(gmdate('Y-m-d', $corte));
    $caduca     = time() - VENTANA_DIAS * 86400;
    $previas    = 0;
    $caducadas  = 0;
    $sin_fecha  = 0;

    $publicables = [];
    foreach ($filas as $fila) {
        // Las que trae el catálogo de KEV no se miden por cuándo se publicó la CVE
        // —casi todas son de hace años— sino por cuándo entraron en el catálogo,
        // que es lo que ahí es noticia. Y caducan igual que el resto: a los 14 días
        // de entrar salen del feed, que es lo que impide que se vuelvan a acumular
        // las ~1.700 de siempre.
        if (($fila['fueraDeVentana'] ?? false) === true) {
            $entrada = is_string($fila['kev']['fecha'] ?? null) ? strtotime($fila['kev']['fecha']) : false;
            if ($entrada === false) {
                $sin_fecha++;
            } elseif ($entrada < $corte_dia) {
                $previas++;
            } elseif ($entrada < $caduca) {
                $caducadas++;
            } else {
                $publicables[] = $fila;
            }
            continue;
        }

        // Para el resto la caducidad ya la pone la propia ventana de la descarga:
        // lo que se pide a la EUVD son los últimos VENTANA_DIAS días y punto.
        $cuando   = $fila['fecha'] ?? $fila['actualizado'] ?? null;
        $publicada = is_string($cuando) ? strtotime($cuando) : false;
        if ($publicada === false) {
            $sin_fecha++;
        } elseif ($publicada < $corte) {
            $previas++;
        } else {
            $publicables[] = $fila;
        }
    }

    log_linea('Corte en ' . SYNC_CORTE . ': publico ' . count($publicables) . ' de ' . count($filas)
        . ' filas (' . $previas . ' anteriores al corte, ' . $caducadas . ' de KEV pasadas de '
        . VENTANA_DIAS . ' días, ' . $sin_fecha . ' sin fecha que mirar)');

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
$entradas_kev = pedir_kev();
sembrar_kev($registros, $entradas_kev, $cache_kev);

$filas = array_values($registros);

usort($filas, static function (array $a, array $b): int {
    return strcmp((string) $b['fecha'], (string) $a['fecha']);  // más recientes primero
});

completar_meta($filas, $cache_meta);
completar_cwes_nvd($filas, $cache_cwes, $nvd_clave, $nvd_pausa_us, $rapido);
completar_epss($filas, $cache_epss, $rapido);
completar_kev($filas, $entradas_kev);

// Se filtra al final, con las filas ya enriquecidas: así el corte mira la fecha
// de entrada en KEV, que la pone completar_kev(). Lo que salga de aquí es lo que
// se publica y lo único de lo que Telegram llega a enterarse.
$publicables = aplicar_corte($filas);

$salida = [
    'generado'      => gmdate('c'),
    'ventanaDias'   => VENTANA_DIAS,
    'corte'         => SYNC_CORTE !== '' ? SYNC_CORTE : null,  // desde cuándo se acumula
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
    'fuenteKev'     => 'CISA KEV y EU KEV, vía EUVD',
    'fuenteCwe'     => 'cve.org, con el NVD de respaldo',
    'items'         => $publicables,
];

if (!escribir_json($destino, $salida)) {
    exit(1);
}

log_linea('Escritas ' . count($publicables) . ' vulnerabilidades en ' . $destino
    . ' (' . ($rapido ? 'pasada rápida' : 'pasada completa') . ')');

notificar_telegram($publicables, $tg_token, $tg_salas, $tg_chat, $tg_umbral, $estado_telegram);
