# Agent-Defense-Force — narrated walkthrough.
# STATIC FILE SERVING ONLY. No application backend, no Jac app, no gateway,
# no mesh, no credentials. nginx serves the walkthrough/ directory and nothing else.
FROM nginx:alpine

# Drop nginx's default landing page before copying ours in.
RUN rm -rf /usr/share/nginx/html/*

# Only the walkthrough assets. .dockerignore keeps secrets, runs/, var/,
# .cotal/, .env, graphify-out/, stt/ and frames/ out of the build context.
COPY walkthrough/ /usr/share/nginx/html/

# Belt-and-braces: even if the build context ever leaks these in, they never ship.
RUN rm -rf /usr/share/nginx/html/graphify-out \
           /usr/share/nginx/html/stt \
           /usr/share/nginx/html/frames \
           /usr/share/nginx/html/CLAUDE.local.md \
           /usr/share/nginx/html/.env

COPY nginx-walkthrough.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
