FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY index.html postcss.config.js tailwind.config.js vite.config.js ./
COPY src ./src
COPY public ./public
# Seed the build output with the previous release's lazy chunks. Vite keeps
# these compatibility assets while producing the new single-bundle app.
COPY web/assets/js ./web/assets/js
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/web/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
