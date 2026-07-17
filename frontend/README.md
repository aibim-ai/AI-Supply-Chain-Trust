# Frontend

Static frontend deployment boundary for AI Supply Chain Trust.

- `web/`: browser app shell, assets, brand files, robots/sitemap/llms metadata.
- `Dockerfile`: builds the frontend Nginx image.
- `nginx.conf`: serves `web/` as an SPA with long-lived asset caching.

Production frontend responsibilities:

- `/`
- `/assets/*`
- extensionless SPA routes such as `/leaderboard`, `/docs`, `/about`

API, MCP, security context artifacts, and health routes are owned by the
backend and routed by the edge Nginx proxy.

## Analytics configuration

Analytics loads only after the visitor grants consent. Google Tag Manager uses
container `GTM-5X8L82L8` by default and can be overridden at build time with
`VITE_GTM_CONTAINER_ID`. Product events are pushed to `dataLayer` as GTM custom
events; repository names and other sensitive values are removed by the event
allowlist before delivery.
