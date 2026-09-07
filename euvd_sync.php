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
const VENTANA_DIAS = 14;      // cuántos días hacia atrás pedir
const PAGE_SIZE    = 100;     // máximo que admite la API
// La ventana de 14 días ronda las 5.000 vulnerabilidades, así que 25 páginas se
// quedaban con la mitad —y no con la mitad más reciente, sino con las que
// devolviera la API—. El tope sigue existiendo por seguridad, pero ahora holgado.
const MAX_PAGINAS  = 60;      // tope de seguridad: 60 * 100 = 6.000 registros
const PAUSA_US     = 400000;  // 0,4 s entre peticiones, para no castigar la API
const TIMEOUT      = 30;
const CONCURRENCIA_TITULOS = 6;    // peticiones simultáneas a cve.org
const TANDA_TITULOS        = 300;  // cada cuántos títulos deja una línea de log

const API_EPSS      = 'https://api.first.org/data/v1/epss';  // probabilidad de explotación (FIRST)
const EPSS_TANDA    = 100;     // máximo de CVE que admite una petición a FIRST
const EPSS_PAUSA_US = 300000;

const API_NVD          = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_PAGE         = 2000;  // máximo que admite la API del NVD
const NVD_MAX_PAGINAS  = 15;    // tope de seguridad: 15 * 2.000 = 30.000 CVE
const NVD_MARGEN_DIAS  = 30;    // se pide más ventana de la necesaria; ver completar_scores()

const TG_API          = 'https://api.telegram.org/bot';
const TG_MAX_MENSAJES = 12;       // avisos por sala y pasada; lo que sobre se manda en la siguiente
const TG_PAUSA_US     = 1200000;  // Telegram corta a ~1 mensaje/s por chat

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
 * KEV; el CVSS del NVD y la EPSS se leen de la caché en vez de pedirse.
 *
 * Tiene sentido porque las fuentes no cambian al mismo ritmo: el modelo EPSS se
 * recalcula una vez al día y el NVD tarda en enriquecer, mientras que lo único
 * que trae vulnerabilidades nuevas es el listado. Así se puede pasar cada 15
 * minutos por 40 s en vez de por 190 s, y dejar la pasada completa cada 6 horas.
 */
$rapido = in_array('--rapido', $argv ?? [], true) || getenv('SYNC_RAPIDO') === '1';

$destino = __DIR__ . '/data/cves.json';
$cerrojo_ruta = __DIR__ . '/.sync.lock';
$cache_meta   = __DIR__ . '/data/cve_meta.json';   // título y CWE de cve.org
$cache_scores = __DIR__ . '/data/scores_nvd.json';
$cache_epss   = __DIR__ . '/data/epss.json';
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

// ---------------------------------------------------------------- CVSS y CWE del NVD

/**
 * Del bloque `metrics` del NVD saca la métrica CVSS más moderna disponible,
 * prefiriendo la primaria (la del propio NIST o del CNA) sobre las secundarias.
 *
 * @return array{score:float,cvss:?string,vector:?string}|null
 */
function metrica_nvd(?array $metrics): ?array
{
    foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $clave) {
        $lista = $metrics[$clave] ?? null;
        if (!is_array($lista) || $lista === []) continue;

        $elegida = $lista[0];
        foreach ($lista as $m) {
            if (($m['type'] ?? null) === 'Primary') {
                $elegida = $m;
                break;
            }
        }

        $datos = $elegida['cvssData'] ?? null;
        if (!isset($datos['baseScore'])) continue;

        return [
            'score'  => (float) $datos['baseScore'],
            'cvss'   => $datos['version'] ?? null,
            'vector' => $datos['vectorString'] ?? null,
        ];
    }
    return null;  // CVE recibida pero sin analizar todavía ("Awaiting Analysis")
}

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
 * Baja del NVD todas las CVE publicadas en un rango de fechas, paginando.
 *
 * @return array<string,array{score?:float,cvss?:?string,vector?:?string,cwes:array<int,array{id:string,nombre:?string}>}>
 */
function pedir_scores_nvd(string $desde_iso, string $hasta_iso, string $clave, int $pausa_us): array
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
            log_linea('El NVD falló; me quedo con las puntuaciones que ya tenga.');
            break;
        }

        $vulns = $respuesta['vulnerabilities'] ?? [];
        if (!is_array($vulns) || count($vulns) === 0) {
            break;
        }

        foreach ($vulns as $entrada) {
            $id = $entrada['cve']['id'] ?? null;
            if (!is_string($id)) continue;

            $metrica = metrica_nvd($entrada['cve']['metrics'] ?? null);
            $cwes    = cwes_de_nvd($entrada['cve']['weaknesses'] ?? null);

            // Guardamos la entrada aunque solo traiga CWE: el NVD tarda en puntuar,
            // pero la debilidad suele venir desde el primer momento.
            if ($metrica !== null || $cwes !== []) {
                $salida[$id] = ($metrica ?? []) + ['cwes' => $cwes];
            }
        }

        $total = (int) ($respuesta['totalResults'] ?? 0);
        log_linea('NVD página ' . $pagina . ': ' . count($vulns) . ' CVE (con CVSS acumuladas: ' . count($salida) . ')');

        if (($pagina + 1) * NVD_PAGE >= $total) {
            break;
        }
        usleep($pausa_us);
    }

    return $salida;
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
 *
 * @param array<int,array<string,mixed>> $filas
 */
function completar_scores(array &$filas, string $cache_ruta, string $clave, int $pausa_us, bool $rapido): void
{
    $cache = leer_cache($cache_ruta);

    $desde_iso = gmdate('Y-m-d\TH:i:s.000', strtotime('-' . (VENTANA_DIAS + NVD_MARGEN_DIAS) . ' days'));
    $hasta_iso = gmdate('Y-m-d\TH:i:s.000');

    // En modo rápido no se pregunta al NVD: es la fase más lenta con diferencia y
    // el enriquecimiento no va a cambiar en quince minutos.
    // Lo recién bajado manda sobre la caché.
    $scores = $rapido
        ? $cache
        : pedir_scores_nvd($desde_iso, $hasta_iso, $clave, $pausa_us) + $cache;

    $vigentes = [];
    $con_nvd  = 0;
    foreach ($filas as &$fila) {
        $cve = $fila['cve'];
        $nvd = is_string($cve) ? ($scores[$cve] ?? null) : null;
        if ($nvd === null) continue;

        if (isset($nvd['score'])) {
            $fila['score']       = $nvd['score'];
            $fila['severidad']   = severidad($nvd['score']);
            $fila['cvss']        = $nvd['cvss'] ?? $fila['cvss'];
            $fila['vector']      = $nvd['vector'] ?? $fila['vector'];
            $fila['origenScore'] = 'nvd';
            $con_nvd++;
        }
        // El NVD solo completa las CWE que cve.org no haya dado: allí vienen con nombre.
        if (($nvd['cwes'] ?? []) !== []) {
            $fila['cwes'] = fusionar_cwes($fila['cwes'], $nvd['cwes']);
        }

        $vigentes[$cve] = $nvd;
    }
    unset($fila);

    // Igual que con los títulos: la caché se queda solo con lo que sigue en ventana.
    escribir_json($cache_ruta, $vigentes);
    log_linea($con_nvd . ' de ' . count($filas) . ' filas con CVSS del NVD'
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
 * Marca las filas que están en el catálogo de vulnerabilidades explotadas: CISA
 * KEV y EU KEV, que la EUVD consolida y sirve de una vez en /api/kev/dump.
 *
 * Es el complemento de la EPSS, no un duplicado: la EPSS estima la probabilidad
 * de que alguien la explote, el KEV dice que ya lo está haciendo. Y no se parecen
 * (de las que caen en KEV, la mayoría anda por debajo del 1 % de EPSS), así que
 * ordenar por EPSS las entierra. Una sola petición, sin paginar.
 *
 * @param array<int,array<string,mixed>> $filas
 */
function completar_kev(array &$filas): void
{
    $dump = pedir(API_KEV);
    $entradas = null;

    if (is_array($dump)) {
        $entradas = isset($dump[0]) ? $dump : ($dump['items'] ?? null);
    }
    if (!is_array($entradas)) {
        log_linea('KEV: no pude leer el catálogo; las filas se quedan sin marcar.');
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
        'score'       => $score,
        'severidad'   => severidad($score),
        // La EUVD manda 0 cuando no hay CVSS: eso no es una puntuación, es un hueco.
        // Lo pisa completar_scores() si el NVD tiene puntuación para esta CVE.
        'origenScore' => ($score !== null && $score > 0.0) ? 'euvd' : null,
        'cvss'        => $item['baseScoreVersion'] ?? null,
        'vector'      => $item['baseScoreVector'] ?? null,
        'cwes'        => [],  // lo rellenan completar_meta() y completar_scores()
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
 * Las salas, de menos a más prioridad. Este orden decide dos cosas: a qué sala
 * va una fila que encaja en varias —KEV manda sobre la puntuación— y qué cuenta
 * como escalar, porque solo se reavisa hacia arriba.
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
 * $previa solo llega cuando es un reaviso por escalada, y entonces el mensaje
 * abre diciéndolo: en la sala de KEV, la mitad de los mensajes son CVE de las
 * que ya se avisó hace días, y sin ese aviso parecen recién publicadas.
 *
 * @param array<string,mixed>      $fila
 * @param array<string,mixed>|null $previa
 */
function mensaje_telegram(array $fila, ?array $previa = null): string
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
        $lineas[] = "\u{2B06}\u{FE0F} <b>Escalated</b> — previously reported as " . $antes . $cuando;
        $lineas[] = '';
    }

    $marca      = $marcas[$fila['severidad']] ?? $marcas['sin_puntuar'];
    $puntuacion = $fila['score'] !== null
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

    if ($fila['origenScore'] === 'euvd') {
        $datos[] = '<b>Score:</b> EUVD, pending NVD analysis';
    }
    if (is_string($fila['fecha'])) {
        $datos[] = '<b>Published:</b> ' . substr($fila['fecha'], 0, 10);
    }

    if (count($datos) > 0) {
        $lineas[] = '';
        $lineas   = array_merge($lineas, $datos);
    }

    $enlaces = [];
    if (is_string($fila['enlace'])) {
        $enlaces[] = '<a href="' . escapar_html($fila['enlace']) . '">NVD</a>';
    }
    if (is_string($fila['cve'])) {
        $enlaces[] = '<a href="https://www.cve.org/CVERecord?id=' . escapar_html($fila['cve']) . '">CVE Record</a>';
    }
    if (count($enlaces) > 0) {
        $lineas[] = '';
        $lineas[] = implode(' · ', $enlaces);
    }

    return implode("\n", $lineas);
}

/**
 * Manda un mensaje. Devuelve si se envió y, cuando Telegram pide esperar (429),
 * cuántos segundos.
 *
 * @return array{enviado: bool, esperar: int}
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

    $ch = curl_init(TG_API . $token . '/sendMessage');
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
        log_linea("Telegram: cURL falló: {$error}");
        return ['enviado' => false, 'esperar' => 0];
    }

    $json = json_decode((string) $respuesta, true);
    if ($codigo === 200 && ($json['ok'] ?? false) === true) {
        return ['enviado' => true, 'esperar' => 0];
    }

    log_linea("Telegram: HTTP {$codigo} en {$destino} " . ($json['description'] ?? ''));
    return ['enviado' => false, 'esperar' => (int) ($json['parameters']['retry_after'] ?? 0)];
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
    // reaviso de escalada por cada fila que antes no tenía sala anotada.
    $formato_viejo = false;
    foreach ($previas as $entrada) {
        if (!is_array($entrada)) {
            $formato_viejo = true;
            break;
        }
    }
    $primera_vez = !is_string($estado['sembrado'] ?? null);

    // La poda: nos quedamos con lo que sigue dentro de la ventana, como las demás
    // cachés, para que el fichero no crezca sin fin.
    $vigentes = [];
    foreach ($filas as $fila) {
        if (isset($previas[$fila['euvd']])) {
            $vigentes[$fila['euvd']] = $previas[$fila['euvd']];
        }
    }

    $ahora = gmdate('c');

    if ($primera_vez || $formato_viejo) {
        foreach ($filas as $fila) {
            $vigentes[$fila['euvd']] = ['sala' => sala_de($fila), 'fecha' => $ahora, 'enviada' => false];
        }
        escribir_json($estado_ruta, [
            'sembrado' => is_string($estado['sembrado'] ?? null) ? $estado['sembrado'] : $ahora,
            'avisadas' => $vigentes,
        ]);
        log_linea('Telegram: ' . ($primera_vez ? 'primera ejecución' : 'estado en formato antiguo')
            . ', siembro ' . count($filas) . ' vulnerabilidades sin avisar. A partir de la siguiente '
            . 'pasada solo llega lo nuevo.');
        return;
    }

    // Nuevas y escaladas. Las que no tengan sala montada se anotan aquí mismo y no
    // vuelven a mirarse mientras no suban de sala.
    $candidatas = [];

    foreach ($filas as $fila) {
        $sala   = sala_de($fila);
        $previa = $vigentes[$fila['euvd']] ?? null;

        if ($previa !== null && prioridad_sala($sala) <= prioridad_sala((string) $previa['sala'])) {
            continue;
        }

        $destino = destino_de($sala, $fila, $salas, $respaldo, $umbral);
        if ($destino === '') {
            $vigentes[$fila['euvd']] = ['sala' => $sala, 'fecha' => $ahora, 'enviada' => false];
            continue;
        }

        $candidatas[] = [
            'fila'    => $fila,
            'sala'    => $sala,
            'destino' => $destino,
            'previa'  => ($previa !== null && ($previa['enviada'] ?? false)) ? $previa : null,
        ];
    }

    if (count($candidatas) === 0) {
        log_linea('Telegram: nada nuevo que avisar.');
        escribir_json($estado_ruta, ['sembrado' => $estado['sembrado'], 'avisadas' => $vigentes]);
        return;
    }

    // Por sala y luego por puntuación: si un día hay atasco, lo que ya se está
    // explotando sale delante.
    usort($candidatas, static function (array $a, array $b): int {
        return (prioridad_sala($b['sala']) <=> prioridad_sala($a['sala']))
            ?: ((float) ($b['fila']['score'] ?? 0) <=> (float) ($a['fila']['score'] ?? 0));
    });

    $enviadas = [];
    $total    = 0;
    $cortado  = false;

    foreach ($candidatas as $c) {
        // El tope es por sala: el límite de Telegram es por chat, así que un atasco
        // en medias no tiene por qué retrasar el aviso de una crítica.
        $cupo = ($enviadas[$c['sala']] ?? 0) + 1;
        if ($cupo > TG_MAX_MENSAJES) {
            continue;  // se queda sin marcar: sale en la siguiente pasada
        }

        if ($total > 0) {
            usleep(TG_PAUSA_US);
        }

        $resultado = telegram_enviar($token, $c['destino'], mensaje_telegram($c['fila'], $c['previa']));

        if ($resultado['enviado']) {
            $vigentes[$c['fila']['euvd']] = ['sala' => $c['sala'], 'fecha' => $ahora, 'enviada' => true];
            $enviadas[$c['sala']] = $cupo;
            $total++;
        } elseif ($resultado['esperar'] > 0) {
            // 429: Telegram dice cuánto callar. Cortamos y lo retomamos en la pasada
            // siguiente; lo no enviado se queda sin marcar, así que no se pierde.
            log_linea('Telegram: me pide esperar ' . $resultado['esperar']
                . ' s; lo dejo para la siguiente pasada.');
            $cortado = true;
            break;
        }
    }

    escribir_json($estado_ruta, ['sembrado' => $estado['sembrado'], 'avisadas' => $vigentes]);

    $desglose = [];
    foreach ($enviadas as $sala => $n) {
        $desglose[] = $sala . ' ' . $n;
    }
    $cola = count($candidatas) - $total;

    log_linea('Telegram: ' . $total . ' avisos enviados'
        . (count($desglose) > 0 ? ' (' . implode(', ', $desglose) . ')' : '')
        . ($cola > 0 ? ', ' . $cola . ' para la siguiente pasada' . ($cortado ? ' (me cortaron)' : '') : ''));
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

$filas = array_values($registros);

usort($filas, static function (array $a, array $b): int {
    return strcmp((string) $b['fecha'], (string) $a['fecha']);  // más recientes primero
});

completar_meta($filas, $cache_meta);
completar_scores($filas, $cache_scores, $nvd_clave, $nvd_pausa_us, $rapido);
completar_epss($filas, $cache_epss, $rapido);
completar_kev($filas);

$salida = [
    'generado'      => gmdate('c'),
    'ventanaDias'   => VENTANA_DIAS,
    'modo'          => $rapido ? 'rapido' : 'completo',
    'desde'         => $desde,
    'hasta'         => $hasta,
    'total'         => count($filas),
    'totalEnEuvd'   => $total_api,
    'fuente'        => 'EU Vulnerability Database (ENISA)',
    'fuenteScore'   => 'NVD (NIST), con la EUVD de respaldo',
    'fuenteEpss'    => 'EPSS de FIRST',
    'fuenteKev'     => 'CISA KEV y EU KEV, vía EUVD',
    'fuenteCwe'     => 'cve.org, con el NVD de respaldo',
    'items'         => $filas,
];

if (!escribir_json($destino, $salida)) {
    exit(1);
}

log_linea('Escritas ' . count($filas) . ' vulnerabilidades en ' . $destino
    . ' (' . ($rapido ? 'pasada rápida' : 'pasada completa') . ')');

notificar_telegram($filas, $tg_token, $tg_salas, $tg_chat, $tg_umbral, $estado_telegram);
