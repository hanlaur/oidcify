#!/bin/bash

set -e

export KONG_DATABASE=off
export KONG_PLUGINS=bundled,kong-plugin-freeoidc
export KONG_PLUGINSERVER_NAMES=kong-plugin-freeoidc
export KONG_PLUGINSERVER_KONG_PLUGIN_FREEOIDC_SOCKET="/tmp/kongprefix/kong-plugin-freeoidc.socket"
export KONG_PLUGINSERVER_KONG_PLUGIN_FREEOIDC_QUERY_CMD="../kong-plugin-freeoidc -dump"
export KONG_PLUGINSERVER_KONG_PLUGIN_FREEOIDC_START_CMD="../kong-plugin-freeoidc --kong-prefix /tmp/kongprefix"
export KONG_PROXY_LISTEN="0.0.0.0:8000, 0.0.0.0:8443 ssl"
export KONG_ADMIN_LISTEN="0.0.0.0:8001, 0.0.0.0:8444 ssl"
export KONG_STATUS_LISTEN=0.0.0.0:8100
export KONG_LOG_LEVEL=debug
export KONG_PROXY_BUFFER_SIZE=128k
export KONG_NGINX_PROXY_LARGE_CLIENT_HEADER_BUFFERS="4 128k"
export KONG_ANONYMOUS_REPORTS=off
export KONG_NGINX_DAEMON=off
export KONG_PROXY_ACCESS_LOG=/dev/stdout
export KONG_ADMIN_ACCESS_LOG=/dev/stdout
export KONG_PROXY_ERROR_LOG=/dev/stderr
export KONG_ADMIN_ERROR_LOG=/dev/stderr

export KONG_DECLARATIVE_CONFIG=./temp-kong-local.yml

rm -rf /tmp/kongprefix

#kong start --conf ./kong-local.yml --prefix /tmp/kongprefix -vv

source oidc.env
envsubst < ./kong-local.yml > ./temp-kong-local.yml
kong prepare --prefix /tmp/kongprefix --conf ./temp-kong-local.yml
/usr/local/openresty/nginx/sbin/nginx -p /tmp/kongprefix -c /tmp/kongprefix/nginx.conf 
