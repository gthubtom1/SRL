# site-clone02 artifacts

Target: `https://example.com/` (public static single page, GET only, 2 rps).

```bash
python Tool/skill/site-clone/scripts/site-crawl.py --url https://example.com/ \
  --out Tool/cases/site-clone02/artifacts/crawl --max-pages 5 --max-depth 2 --rps 2
python Tool/skill/site-clone/scripts/site-rebuild.py \
  --crawl Tool/cases/site-clone02/artifacts/crawl \
  --out Tool/cases/site-clone02/artifacts/rebuild --rps 2
python Tool/skill/site-clone/scripts/site-diff.py \
  --crawl Tool/cases/site-clone02/artifacts/crawl \
  --rebuild Tool/cases/site-clone02/artifacts/rebuild \
  --out Tool/cases/site-clone02/artifacts/diff.json
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone02 --write
```

Result: PASS (6/6), 1 route, pixel 0.0, DOM 1.0, 404 0, external 0, interactions 8/8.
External link `iana.org` was rewritten to `#` + `data-original-href`; no live external request.
