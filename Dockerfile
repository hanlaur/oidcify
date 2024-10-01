FROM kong:3.8.0
COPY oidcify /usr/local/bin/
COPY README.md NOTICE LICENSE /usr/local/share/doc/oidcify/
COPY component_licenses /usr/local/share/doc/oidcify/component_licenses
ENV KONG_PLUGINSERVER_NAMES="oidcify"
ENV KONG_PLUGINSERVER_OIDCIFY_QUERY_CMD="/usr/local/bin/oidcify -dump"
ENV KONG_PLUGINSERVER_OIDCIFY_START_CMD="/usr/local/bin/oidcify"
ENV KONG_PLUGINS=bundled,oidcify
