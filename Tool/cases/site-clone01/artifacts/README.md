# site-clone01 artifacts

Target: `https://block.youtest.me/` (authorized, GET only, 2 rps).

```bash
python Tool/skill/site-clone/scripts/site-crawl.py --url https://block.youtest.me/ \
  --out Tool/cases/site-clone01/artifacts/crawl \
  --max-pages 20 --max-depth 3 --rps 2 --allow-host api.youtest.me
python Tool/skill/site-clone/scripts/site-rebuild.py \
  --crawl Tool/cases/site-clone01/artifacts/crawl \
  --out Tool/cases/site-clone01/artifacts/rebuild --rps 20
python Tool/skill/site-clone/scripts/site-diff.py \
  --crawl Tool/cases/site-clone01/artifacts/crawl \
  --rebuild Tool/cases/site-clone01/artifacts/rebuild \
  --out Tool/cases/site-clone01/artifacts/diff.json
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone01 --write
```

Result: PASS (6/6), missing_rate 0.0, pixel raw_max 0.0282 / masked 0.0040 (SPA threshold 0.03),
DOM 1.0, 404 0, external 0, interactions 9/10, backend_required 9.

`backend_required` = `/find`, `/player/completed`, `/player/name`, `/player/playing`,
`/user/creating`, `/user/scoreboard`, `/user/scoreboard/answers`, `/user/share`,
`https://api.youtest.me/info/country`.
