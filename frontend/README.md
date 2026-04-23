# Frontend Quickstart

## Install

```bash
cd frontend
npm ci
```

## Development

```bash
npm run dev
```

Open:

```text
http://127.0.0.1:3000
```

## Production

```bash
npm run build
npm run start -- --hostname 127.0.0.1 --port 3000
```

## Notes

- The frontend uses Next.js App Router.
- `/api/run-agent` starts the root project command `uv run main.py -t ...`.
- Reports are read from `../reports`.
- Tool, skill, RAG, and CVE data reuse the main project directories directly.
- Configure the root `.env` first and make sure `uv sync` has been run in the main project.
- If command execution is needed, start the Kali container under `docker/` first.
