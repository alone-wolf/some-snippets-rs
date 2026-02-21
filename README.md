# some-snippets

A small Axum + SeaORM service that exposes generic CRUD APIs for snippet-related resources.

## Run

```bash
cargo run
```

Default bind: `127.0.0.1:3000`  
Default database: `sqlite://snippets.db?mode=rwc` (override with `DATABASE_URL`).

## API

- `GET /ping`
- CRUD (under `/api/v1`):
  - `/collections`
  - `/files`
  - `/histories`
  - `/nodes`
  - `/snippets`
  - `/tags`
  - `/texts`

Each CRUD resource provides:

- `GET /`
- `POST /`
- `GET /:id`
- `PUT /:id`
- `DELETE /:id`

`GET /` supports pagination query params:

- `page` (default: `1`)
- `page_size` (default: `20`, clamped to `1..=200`)

## Notes

- Tables are created by SeaORM migration in `migration/src/m20260215_000001_create_tables.rs`.
- `snippets.connection_id` references `collections.id`.
- `nodes.snippet_id` references `snippets.id`.
