# Deployment

The service runs as a container. The retrieval index and both reference
snapshots are built into the image, so a running instance needs no network
access and cannot be broken by an upstream source being unavailable.

## Render

1. Push the repository to GitHub.
2. In the Render dashboard choose **New → Blueprint** and select the
   repository. `render.yaml` describes the service, so no manual configuration
   is required.
3. Optionally add `GEMINI_API_KEY` under **Environment**. Without it the
   service still produces the full report using deterministic narration.
4. The first build takes roughly five minutes, most of it embedding the
   control catalogue. Subsequent builds reuse the cached layer.

Health checks use `/health`, which answers without touching the report
pipeline, so a slow report never causes a restart loop.

### Free instance behaviour

A free instance sleeps after a period without traffic, and the next request
wakes it. Waking takes some tens of seconds. That is a property of the plan
rather than of the service; a paid instance or an external uptime check removes
it.

## Any container host

```bash
docker build -t cyber-risk-assistant .
docker run -p 8000:8000 cyber-risk-assistant
```

The image listens on `$PORT` when the platform sets one, and on 8000
otherwise.

## Configuration in production

Set `APP_ENV=production`. This switches logging to JSON lines for ingestion by
any aggregator, and removes the local diagnostic endpoint.

Set `DEMO_ACCESS_TOKEN` to require a shared token on the report endpoints.
Callers then supply it as an `X-Access-Token` header or a `token` query
parameter. Left unset, the report is public.

## Verifying a deployment

```bash
curl -sf https://<host>/health          # liveness
curl -sf https://<host>/ready           # index size and configured providers
curl -sf https://<host>/report | head   # the report itself
```

`/ready` reports how many controls are indexed. A value of zero means the
image was built without the index and the deployment should be rejected.
