# License Audit

This project is licensed under Apache-2.0. Dependencies keep their own
licenses.

Run the local helper:

```bash
make license-check
```

The helper scans compiled Go package dependencies with `go list -deps -json`
and verifies each module's top-level license files. It requires only Go and
Python 3.

The default policy allows common Apache-2.0-compatible licenses used by
the current dependency set: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause,
ISC, BlueOak-1.0.0, 0BSD, and MPL-2.0.

CI runs `make license-check` on pushes and pull requests. By default the helper
checks distribution dependencies. To include test-only dependencies, run:

```bash
INCLUDE_TEST_DEPS=1 make license-check
```

## Current Findings

The project is Go-only today. The license check covers the package graph
compiled from `./...`; it does not approve copied third-party files, generated
assets, examples, templates, or vendored code. Before adding those, record the
source and license and keep incompatible licenses out of this repository.

Do not add GPL, AGPL, LGPL, proprietary, or unknown-license code unless the
licensing implications have been reviewed.
