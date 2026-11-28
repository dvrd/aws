# Working on aws

`aws` is an Odin library, imported as `shared:aws`, that signs and sends S3 and SES requests and resolves AWS credentials. `README.md` lists what it offers, and `src/doc.odin` holds the API contracts (`odin doc src`). Every task is a command of `cmd/tasks`, an Odin program that `task` builds to `build/tasks`.

## Prerequisites

- The Odin fork at `~/dev/oss/Odin`. Check: `odin version`. `ODIN_COMMIT` records the fork commit the suites are tested with; `task deps` reports drift from the pins.
- `krs`, with the packages pinned in `.krs/packages.json` (`async`, `surf`) installed or linked into the shared collection. Check: `krs --version`, then `task deps`. Use `krs install`, `krs update <pkg>@<tag>` and `krs link <pkg>`; never edit the shared collection by hand.
- `openssl` on `PATH`: `cmd/tasks/signatures.odin` runs `openssl dgst` to check SigV4 signatures independently. Check: `openssl version`.
- For the sanitized tasks (`test:credentials`, `test:loopback`, `test:native-errors`), a clang whose major version equals Odin's LLVM backend. Check: `odin report | grep LLVM`, then install `llvm@<N>`. `sanitizer_clang_select` in `cmd/tasks/common.odin` looks in `/opt/homebrew/opt/llvm@<N>/bin/clang`, `/usr/local/opt/llvm@<N>/bin/clang` and `/usr/lib/llvm-<N>/bin/clang`. If neither a versioned clang nor the system clang matches the `Backend: LLVM` major and no `ODIN_CLANG_PATH` is set, the task stops with `need clang <N>`.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `ODIN` | `odin` | the compiler |
| `WEBTOOLS_SHARED` | `~/dev/oss/Odin/shared` | the shared collection that provides the dependencies |
| `ODIN_CLANG_PATH` | picked by `sanitizer_clang_select` | linker clang for sanitized builds; used as is when already set |

The library itself reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_CREDENTIAL_EXPIRATION`, `AWS_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE`, `HOME`, `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, `AWS_EC2_METADATA_DISABLED` (exactly `true` disables IMDS), and in `load_s3_config` `AWS_S3_BUCKET`, `AWS_REGION` and `AWS_DEFAULT_REGION`. `AWS_CONTAINER_CREDENTIALS_FULL_URI` and `AWS_WEB_IDENTITY_TOKEN_FILE` are refused.

## Commands

Run `task --list` for the current set.

- `task check`: type-check and run every offline test.
- `task check:fast`: type-check and run the unit tests; the inner loop before `task check`.
- `task hooks:install`: run `task check` on each pushed commit (sets `core.hooksPath`).
- `task build`: type-check the library with vet and warnings as errors.
- `task test`: run the Odin suites. The fast loop is `task test -- --package unit`; `-- --package unit/tasks` runs the task runner's tests; `task test -- -- -define:ODIN_TEST_NAMES=aws.<test_name>` runs one test.
- `task test:layout`: check the test layout rule only.
- `task test:signatures`: recompute the reference SigV4 signatures with OpenSSL.
- `task test:consumer`: build and run a consumer that vendors the library.
- `task test:credentials`, `task test:loopback`, `task test:native-errors`: sanitized runs against fixtures and an owned TLS peer.
- `task deps`: compare the shared collection with the pins in `.krs/packages.json`.
- `task odin:pin`: record the current fork commit in `ODIN_COMMIT`.
- `task qualify -- <command> --state-dir <dir>`: live AWS qualification (see below).
- `task qualify:probe`: build the live qualification probe into `build/probe`.
- `task version`: show the last release and the next one. `task release`: tag the next version.

## Tests

`task test` exits 2 before compiling when the layout rule is violated: every `src/<file>.odin` needs `tests/unit/<file>_test.odin`, every `cmd/<name>/<file>.odin` needs `tests/unit/<name>/<file>_test.odin`, and every unit test file must name an existing source file. Helpers go in `tests/support/<name>/`.

- `tests/unit/`: one `<file>_test.odin` per source file.
- `tests/integration/`: a program end to end through real files and processes.
- `tests/conformance/`: agreement with an independent implementation (botocore reference signatures).
- `tests/fuzz/`: generated inputs against every parser and check.
- `tests/stress/`: concurrency under load.
- `tests/e2e/`: programs the e2e tasks build and run.
- `tests/qualification/`: the probes used against real AWS, and their own tests.
- `tests/support/<name>/`: helpers compiled into every suite of that package.

Every behavior change needs a test. When a documented limit changes, update `src/doc.odin`, `README.md` and `tests/unit/doc_test.odin` together.

## Commits and releases

- Commit subjects follow Conventional Commits, and `!` marks a breaking change. The subjects choose the version.
- The version comes from the subjects since the last `vX.Y.Z` tag: `type!:` or a `BREAKING CHANGE:` footer is major, `feat:` is minor, anything else is patch. Before v1 a breaking change bumps the minor version, and only `task release -- --stable` publishes v1.0.0.
- `task release` tags a clean `main` with an annotated tag listing the subjects. `--push` pushes the tag, and `--allow-drift` releases although the shared collection or compiler differs from its pin. Consumers pin with `krs update aws@<tag>`.
- Commits, tags, pull request descriptions and repository files carry no co-author trailer and no attribution to the tools that helped write them.

## Live qualification

`cmd/qualify` runs against real AWS, and only with `--live`. Everything else is offline.

```
task qualify -- {plan,run,reconcile,cleanup,send,status} --state-dir DIR
    [--resource-plan FILE] [--binary FILE] [--aws-cli FILE]
    [--allow-write] [--ses-sender ADDRESS] [--ses-identity-verified] [--live]
```

`task qualify:probe` builds `build/probe`, the binary that `--binary` takes (an absolute path).

The runner launches the native probe in `tests/qualification/probe/`. It never replays a mutation whose outcome is unknown (`phase_permitted` in `cmd/qualify/runner.odin`). The resource plan is a document with `schema`, `phase` set to `READY`, `bucket` (`webtools-qualification-<suffix>`), `region`, `prefix` (`qualification/<32 hex>/`), `profile` or `credential_source` with `expected_role_arn`, `expected_account` (`<account-id>`), `public_access_block_verified` set to true, and `encryption` set to `AES256`. Keep real account ids, ARNs and bucket names out of the repository: put `--state-dir` and the resource plan outside the checkout, and never commit qualification state, receipts or evidence. Summarise a result worth keeping with placeholder values. The procedure is in `docs/qualification.md`; `docs/qualification.example.json` is a resource plan with placeholder values.
