# some-snippets Web Panel

Vue 3 + TypeScript + Element Plus admin panel for `some-snippets` backend.

## Run

```bash
npm install
npm run dev
```

Default dev URL: `http://127.0.0.1:5173`

Dev proxy is configured to backend `http://127.0.0.1:3000` for:

- `/api/*`
- `/ping`

## Build

```bash
npm run build
```

## Optional environment

- `VITE_API_BASE_URL`  
  If set, requests use this base URL directly instead of dev proxy.
