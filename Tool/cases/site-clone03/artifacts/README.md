# site-clone03 artifacts

Target: local two-page fixture served from `input/site/` on loopback.

```bash
# terminal 1 (fixture directory)
cd Tool/cases/site-clone03/input
cd site
python -m http.server 18766 --bind 127.0.0.1

# terminal 2
python Tool/skill/site-clone/scripts/site-crawl.py --url http://127.0.0.1:18766/ \
  --out Tool/cases/site-clone03/artifacts/crawl --max-pages 5 --max-depth 2 --rps 20
python Tool/skill/site-clone/scripts/site-rebuild.py \
  --crawl Tool/cases/site-clone03/artifacts/crawl \
  --out Tool/cases/site-clone03/artifacts/rebuild --rps 20
python Tool/skill/site-clone/scripts/site-diff.py \
  --crawl Tool/cases/site-clone03/artifacts/crawl \
  --rebuild Tool/cases/site-clone03/artifacts/rebuild \
  --out Tool/cases/site-clone03/artifacts/diff.json
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone03 --write
```

Result: PASS (6/6), 3 routes, pixel 0.0, DOM 1.0, 404 0, external 0, interactions 9/9.
