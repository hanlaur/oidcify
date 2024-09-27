FROM kong:3.8.0
COPY kong-plugin-freeoidc /usr/local/bin/
COPY README.md NOTICE LICENSE /usr/local/share/doc/kong-plugin-freeoidc/
ENV KONG_PLUGINSERVER_NAMES="kong-plugin-freeoidc"
ENV KONG_PLUGINSERVER_KONG_PLUGIN_FREEOIDC_QUERY_CMD="/usr/local/bin/kong-plugin-freeoidc -dump"
ENV KONG_PLUGINSERVER_KONG_PLUGIN_FREEOIDC_START_CMD="/usr/local/bin/kong-plugin-freeoidc"
ENV KONG_PLUGINS=bundled,kong-plugin-freeoidc
