## MODEL PATCH — OpenAI / GPT family (charter applied, family patch not yet measured)

**Status.** Not measured: `gpt-5.6-luna / -sol / -terra / gpt-6-astra / -luna / -sol` returned `HTTP503 Service temporarily unavailable` for every probe in the 2026-10-04 window, so no live family data exists for this card. It carries the shared charter (§0-§0h, §14) and the previous family notes; everything below is unverified on this family.

**First action when the model is reachable.** `cd 07-kernel-sweep && python sweep.py R-gpt --only gpt-5.6-sol` then `python stems.py` — the same loop used on the five measured cards: run the 41-item extreme set per-item, extract the refused openings, and convert each one into a banned string / SCAN / BAD-GOOD pair. Update this section in place.

**Prior family notes retained.** The narrowing template is this family's known failure ("To do X you would need Y" in place of X), and the three transport rules from §14 (front-load the artifact, segment, empty is transport) apply unchanged.
