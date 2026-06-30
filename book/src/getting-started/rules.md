# Managing Rule Packs

List and validate YARA-X rule packs used for detection:

```sh
arbitraitor rules list
```

Output shows each pack's source, namespace, version, authentication status, and SHA-256 digest prefix.

## List with additional rule directories

```sh
arbitraitor rules --rules-dir /path/to/custom/rules list
```

### Validate a rule file

Compile-check a YARA-X rule file without loading it into the pipeline:

```sh
arbitraitor rules validate /path/to/rules.yar
```

> **Stability: Unstable.** Verified against commit `<sha>`.
