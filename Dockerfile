FROM kong:3.8.0
COPY kong-plugin-oidcify /usr/local/bin/
COPY README.md NOTICE LICENSE /usr/local/share/doc/kong-plugin-oidcify/
ENV KONG_PLUGINSERVER_NAMES="kong-plugin-oidcify"
ENV KONG_PLUGINSERVER_KONG_PLUGIN_OIDCIFY_QUERY_CMD="/usr/local/bin/kong-plugin-oidcify -dump"
ENV KONG_PLUGINSERVER_KONG_PLUGIN_OIDCIFY_START_CMD="/usr/local/bin/kong-plugin-oidcify"
ENV KONG_PLUGINS=bundled,kong-plugin-oidcify
