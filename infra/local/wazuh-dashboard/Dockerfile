# Dashboard Wazuh con la marca B89 para el entorno LOCAL (Docker Desktop).
#
# Equivale al modo `repack` de wazuh/dashboard/build.sh sobre la imagen oficial: sustituye los
# activos de marca según assets/targets.tsv e instala los plugins B89 compilados por
# build-plugins.sh (si existen en plugins-dist/). De los parches del core solo se aplica el
# equivalente compilado de 0001 (pantalla de carga: patch-splash.cjs); 0002 (menú de ayuda),
# 0003 (títulos por defecto) y el parche de la app de Wazuh requieren el build desde fuente.
#
# Contextos: el de este directorio + `brand` = wazuh/dashboard (ver compose.wazuh-dashboard-b89.yaml).
ARG WAZUH_VERSION=4.14.8
FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}

USER root
COPY --from=brand assets/ /tmp/b89/assets/
COPY plugins-dist/ /tmp/b89/plugins/
COPY patch-splash.cjs /tmp/b89/patch-splash.cjs
RUN set -eu; \
    R=/usr/share/wazuh-dashboard; \
    sed 's/\r$//' /tmp/b89/assets/targets.tsv | while IFS="$(printf '\t')" read -r src kind dst; do \
      case "$src" in ''|'#'*) continue ;; esac; \
      case "$kind" in \
        dashboard) out="$R/$dst" ;; \
        plugins) out="$R/plugins/wazuh/${dst#plugins/main/}" ;; \
        *) echo "repo desconocido: $kind" >&2; exit 1 ;; \
      esac; \
      test -f "/tmp/b89/assets/$src" || { echo "falta assets/$src" >&2; exit 1; }; \
      mkdir -p "$(dirname "$out")"; cp -f "/tmp/b89/assets/$src" "$out"; \
    done; \
    # Logo del login del Security plugin: va empaquetado con nombre hash (fondo oscuro, texto blanco).
    for f in "$R"/plugins/securityDashboards/target/public/*.svg; do \
      grep -q 'fill:#FFFFFF' "$f" && cp -f /tmp/b89/assets/svg/b89_wordmark_on_dark.svg "$f"; \
      rm -f "$f.br" "$f.gz"; \
    done; \
    "$R/node/bin/node" /tmp/b89/patch-splash.cjs "$R/src/core/server/rendering/views";     chown -R wazuh-dashboard:wazuh-dashboard "$R/src/core/server/core_app/assets" "$R/plugins/wazuh/public/assets/images" "$R/plugins/securityDashboards/target/public"; \
    for zip in /tmp/b89/plugins/*.zip; do \
      [ -f "$zip" ] || continue; \
      echo "Instalando plugin $(basename "$zip")"; \
      su -s /bin/sh wazuh-dashboard -c "$R/bin/opensearch-dashboards-plugin install file://$zip"; \
    done; \
    rm -rf /tmp/b89
USER wazuh-dashboard
