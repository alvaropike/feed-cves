#!/bin/sh
# Avisos de operación por Telegram: que la pasada ha fallado, o que la web se ha
# quedado congelada. No tienen nada que ver con los avisos de vulnerabilidades
# que manda euvd_sync.mjs: aquéllos van a las salas por criticidad y los lee todo
# el que esté en el grupo; éstos son para quien mantiene el montaje.
#
#   sh .github/avisar.sh "texto en HTML de Telegram"
#
# El destino sale de TELEGRAM_CHAT_AVISOS y, si no está puesto, de la sala de KEV
# o del grupo de respaldo, para que un montaje que no haya creado sala propia
# siga enterándose. Sin token o sin destino no manda nada, lo deja escrito en el
# log y sale con 0: un aviso que no se puede entregar no debe además tumbar el
# job que lo lanzaba, y menos cuando ese job ya venía fallando y esto es lo
# último que corre.

set -u

texto="${1:-}"
if [ -z "$texto" ]; then
  echo "avisar.sh: no me han dado texto que mandar."
  exit 0
fi

token="${TELEGRAM_BOT_TOKEN:-}"
destino="${TELEGRAM_CHAT_AVISOS:-}"
[ -n "$destino" ] || destino="${TELEGRAM_CHAT_KEV:-}"
[ -n "$destino" ] || destino="${TELEGRAM_CHAT_ID:-}"

if [ -z "$token" ] || [ -z "$destino" ]; then
  echo "avisar.sh: sin TELEGRAM_BOT_TOKEN o sin ningún destino; el aviso se queda sin mandar:"
  echo "  $texto"
  exit 0
fi

# El tema del foro va pegado al chat con dos puntos (-1001234567890:7), la misma
# forma que usan las salas del sync; esto es partirDestino() en shell.
case "$destino" in
  *:*) chat="${destino%%:*}" ; hilo="${destino#*:}" ;;
  *)   chat="$destino"       ; hilo="" ;;
esac

# Formulario en vez de JSON a propósito: --data-urlencode escapa por nosotros y
# así no hay que escribir a mano un escapador de comillas y saltos de línea para
# un mensaje que puede llevar los dos. Telegram acepta las dos formas.
set -- --data-urlencode "chat_id=$chat"
[ -n "$hilo" ] && set -- "$@" --data-urlencode "message_thread_id=$hilo"
set -- "$@" \
  --data-urlencode "text=$texto" \
  --data-urlencode "parse_mode=HTML" \
  --data-urlencode "disable_web_page_preview=true"

respuesta=$(curl -sS --max-time 20 -X POST \
  "https://api.telegram.org/bot$token/sendMessage" "$@" 2>&1)

case "$respuesta" in
  *'"ok":true'*) echo "avisar.sh: aviso entregado en $chat${hilo:+ (tema $hilo)}." ;;
  *)             echo "avisar.sh: Telegram no lo ha aceptado — $respuesta" ;;
esac

exit 0
