# Provenance

This standalone SDK and CLI were reimplemented from the supplied-content detector model and regression behavior developed for Codaro. Product contracts, identity/access, hosted routes, operational configurations and old advisory tables were excluded. MIT notices for Codaro work are retained in LICENSE.

The earlier incomplete-scan and working-tree staged-scan behavior was replaced with explicit completeness and Git index blob reads. The supported manifest scope is intentionally limited to npm/Composer JSON. All fixtures are synthetic; credential-shaped strings are assembled at test runtime and are not captured credentials. The third-party ignore runtime dependency is MIT licensed and installed separately through package metadata; its code is not copied into this repository.
