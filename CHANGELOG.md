# Changelog

## 0.1.0 - 2026-10-21

Initial standalone public release of codaro-local-check. See README for supported scope and limitations.

Staged input containment resolves Git root aliases (including Windows short paths and junctions) before comparing against the canonical selected root.
Native filesystem canonicalization expands Windows legacy path spellings; an inconsistent Git root is explicitly incomplete rather than an empty successful scan.
