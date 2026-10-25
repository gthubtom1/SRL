> 本篇范围：Pitfalls P1–P8 — packaging, `META-INF/`, dex byte/smali edits and UI patch scope.
> 前后篇：part 1/5 · prev — · next [pitfalls-2-environment-and-evidence.md](pitfalls-2-environment-and-evidence.md) · index [pitfalls.md](pitfalls.md)

# Pitfalls — the failure catalogue

Every entry here cost real time and produced a **silently broken artifact**. Skim this before building. When you lose more than thirty minutes to something new, add it here.

Each entry: **symptom → root cause → why it is hard to see → what to do instead.**

---


**Load this when:** before building anything, and again when a failure looks familiar. It is the failure catalogue: symptom, root cause, why it is hard to see, and what to do instead. Skim it; do not read it linearly.

## P1. Stripping the whole `META-INF/` breaks the app at startup

**Symptom**
```
java.lang.IllegalStateException: Module with the Main dispatcher is missing.
Add dependency providing the Main dispatcher, e.g. 'kotlinx-coroutines-android'
```
App dies immediately on launch. Sometimes a different `ClassNotFoundException` for an unrelated library class.

**Root cause**
`META-INF/` is not only signatures. It holds **ServiceLoader registrations** that Android reads at runtime. Deleting the directory to prepare for re-signing deletes them too.

Real examples found in one APK (framework entries first — these are the ones that produce the
confusing `ClassNotFoundException`; note that **third-party libraries register the same way**, so the
list is not limited to well-known frameworks):
```
META-INF/services/kotlinx.coroutines.internal.MainDispatcherFactory  -> kc
META-INF/services/io.ktor.client.engine.HttpClientEngineContainer    -> OkHttpEngineContainer
META-INF/services/io.ktor.serialization.kotlinx.KotlinxSerializationExtensionProvider
META-INF/services/kotlinx.coroutines.CoroutineExceptionHandler       -> wc
META-INF/services/<third-party-package>.<SomeInterface>              -> <impl class>
META-INF/services/<third-party-package>.<SomeListener>               -> <impl class>
```
The last two are the general shape, not a coincidence: a downloader, an HTTP engine, a serialization
provider or a plugin SPI shipped as a library all land here, and any of them can be the one whose
absence kills startup.

**Why it is hard to see**
The error message names Kotlin coroutines, not your repack. You will spend an hour blaming the dex.

**Do instead**
Strip **only** signature artifacts, and only at the top level of `META-INF/`:

```python
SIG = ('MANIFEST.MF',)
SIG_EXT = ('.SF', '.RSA', '.DSA', '.EC')

def is_signature_entry(name):
    if not name.upper().startswith('META-INF/'):
        return False
    rest = name[len('META-INF/'):]
    if '/' in rest:          # services/, androidx/, native-image/ ... keep
        return False
    up = rest.upper()
    return up in SIG or up.endswith(SIG_EXT)
```

`scripts/repack.py` already does this.

---

## P2. Byte-level string patching without an ordering check rejects the whole dex

**Symptom**
App cannot load any class:
```
ClassNotFoundException: Didn't find class "<App.Application>" on path: DexPathList[[zip file ".../base.apk"]]
```
`Application` construction fails, process never starts.

**Root cause**
Dex requires the `string_ids` table to be **sorted**. Replacing a string with an equal-length string keeps all offsets valid, but changes where that entry *should* sit in the sorted order. If the new value crosses its neighbours, the loader rejects the entire dex.

Concrete case: `/app/adverts` sat between `/api/v1/crashtrack/upload?chk=` and `/app/configs/`. Replacing it with `/app/noadver` put `n` after `c` → out of order → whole dex rejected. Replacing with `/app/blocked` (`b < c`) was accepted.

**Why it is hard to see**
`checksum` (adler32) and `signature` (SHA-1) recompute perfectly, so every integrity check passes. `baksmali` parses the file fine. Only the runtime loader cares about ordering.

**Do instead**
Always run the ordering guard: `scripts/dex_strpatch.py` looks up the target's neighbours in `string_ids` and refuses any replacement outside `(prev, next)`. Pick a candidate that stays inside the interval.

---

## P3. Whole-tree smali round-trip damages R8-optimized dex

**Symptom**
App installs, then dies with:
```
java.lang.IncompatibleClassChangeError: Found interface io.ktor.client.engine.HttpClientEngine,
but class was expected
    at io.ktor.client.engine.HttpClientEngine.access$checkExtensions(...)
```
(or `VerifyError`, or a class-load failure in an unrelated library)

**Root cause**
`baksmali` → `smali` rebuild does not faithfully reproduce R8's synthetic access bridges / optimization artifacts. The class is still declared as an interface, but the bridge method that ART expects to find as a class member is gone.

**Why it is hard to see**
A structural diff of `class_def` entries shows **nothing**: same class count, zero `ACC_INTERFACE` mismatches, zero access-flag differences. The damage is at the code-item / reference level, invisible to table-level checks. It only appears at runtime.

**Do instead**
Use **method-level surgical rewriting** with dexlib2 — read the dex, replace only the target method's implementation, write it back. See `scripts/dexpatch/`. Never rebuild the whole tree for a one-method change.

---

## P4. Rewriting the same dex twice makes ART refuse to start the process

**Symptom**
```
E/ActivityManager: Failure starting process <pkg>
I/ActivityManager: Force stopping <pkg> appid=... user=0: start failure
```
No Java exception anywhere. `logcat` shows a splash screen appearing then vanishing. `baksmali` still parses the dex, and `smali` re-assembles it fine.

**Root cause**
Serializing a dex a second time loses metadata that the first serialization preserved. Chaining two patch tools over the same file (`patch A → patch B → repack`) triggers this.

**Why it is hard to see**
Both intermediate files look valid and round-trip cleanly. Only ART rejects the final one.

**Do instead**
**Combine all edits to one dex into a single read/write pass.** One program, one `loadDexFile`, apply every change, one `writeDexFile`.

---

## P5. Killing an endpoint to hide a UI element takes the whole screen down

**Symptom**
Home screen becomes the app's generic error state ("something went wrong / retry"), or a blank screen, after redirecting or 404-ing an ad endpoint.

**Root cause**
The ad request is a **child request** of the screen's main data load. When it throws, the parent load fails with it.

Concrete case: `/app/adverts` was redirected to a nonexistent path. That endpoint is requested from inside `MainScreenStore.loadData` as a sub-request, so the home screen's entire data load failed.

**Why it is hard to see**
Removing ads *sounds* like it should only remove ads. The coupling is invisible until runtime.

**Do instead**
Suppress at the **data-consumption** or **render** layer, not at the transport layer. Let the request succeed and discard/ignore the result. Never make a shared endpoint fail.

---

## P6. Patching a shared helper breaks unrelated features

**Symptom**
Images stop loading, video playback fails, or downloads break — after patching something that looked ad-specific.

**Root causes, two variants**
- Patching a generic utility: a `Long.valueOf`-style boxing helper had **30+ callers** across player, download, paging and history sync. Patching it would have broken all of them.
- Patching a "card" renderer you assumed was ad-only: the composable's signature was `(itemModel, ColorScheme, Modifier, onClick, ContentScale, Shape, Composer, II)` — a **generic image card** shared by normal content. Making it `return-void` killed all cover art and the player pipeline.

**Why it is hard to see**
The class name and the model type it consumes suggest it is ad-specific. It is not.

**Do instead**
Before patching any method, **count its callers** (`scripts/find_refs.py`). If it has many, or if its parameters look content-generic (image/graphics/`Modifier`/`ContentScale` parameters), it is not specific to your target. Also check whether the parameter model type is shared with non-ad content.

---

## P7. Client-side VIP forgery breaks the app instead of unlocking it

**Symptom**
Blank screen; or logged in, but playback fails.

**Root cause**
The authoritative gate is server-side. Real access is granted by an API response. Forcing the client's local `isVip()` to `true` makes the client believe it has rights the server will not honor, so it walks a path that assumes data it never receives.

Concrete case: `/v2/sections/{id}/play-url` returns **401** with no token and **401** with a forged `Bearer` token; metadata endpoints returned 200 but deliberately omitted any play URL. Patching local VIP state produced a white screen.

**Do instead**
Determine server authority **before** patching. See `references/membership-and-limits.md`. If the gate is server-side, the honest deliverable is "not achievable client-side", plus any genuinely client-side wins (unlocking UI, removing ads).

---

## P8. DataStore / protobuf hand-editing fails silently

**Symptom**
App dies with a bare `uncaughtException` and **no stack trace** (a crash-reporter SDK swallowed it). Or the app launches but ignores your injected value.

**Root cause (encoding)**
AndroidX `Preferences` maps are protobuf `map<string, Value>` fields. An entry needs **two** levels of tag:

```
outer : 0A <len(entry)>
inner : 0A <len(key)> <key>  12 <len(value)> <value>
```

Writing only the inner part produces a file `DataStore` cannot deserialize.

**Root cause (lifecycle)**
`DataStore` caches in memory and writes back. Editing the file while the app runs is either ignored or overwritten. Also the file is owned by the app's uid — a file written as root with the wrong owner is unreadable to the app.

**Do instead**
- Encode with `scripts/datastore_inject.py` (implements both tag levels).
- `force-stop` the app first, write, then start.
- Preserve ownership: write via `su`, then `chown` to the app uid (or `cp -f` over the existing file, which keeps its owner).
- If a value must survive a **fresh install**, code-level patching is the only way — runtime data is not part of the APK.

---

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
