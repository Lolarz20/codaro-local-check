# Privacy

No telemetry, source upload, model API, account or hosted service. Scans use local supplied content; the CLI reads selected local files or staged index blobs. It never modifies source or Git index. Git subprocesses invoke fixed read-only built-in commands directly, without a shell or external diff.

No online lookup runs in the CLI. Importing SDK/CLI helpers makes no network request. The optional explicitly invoked lookupPackage helper sends only one exactly allowlisted package name to the explicitly configured HTTPS registry using HEAD. This reveals the name and caller network address to that registry. Requests have a maximum 30-second timeout, refuse redirects and return unavailable on transport/server failure. No credentials are attached automatically. Existence is not proof of safety; absence is not proof of maliciousness. No lookup cache or source content is sent.

Evidence contains the fixed marker [REDACTED], never a prefix/suffix of a secret. Parser/IO exception messages are replaced with generic failure text, so input echoes cannot leak. Paths and detector IDs are intentionally present in reports. Caller-supplied detector code is trusted; it is responsible for redacting its own findings and terminating. No arbitrary plugin is loaded from disk or remote configuration.
