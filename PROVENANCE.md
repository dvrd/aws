# AWS helper provenance

The original recorded S3 lineage is `src/server/s3.odin`, imported from Saba at
commit `8960e829cae3774ac907714f2360dbc5e205d3aa`. That path, the former
`src/client/buffered_http.odin` adapter and `src/server/PROVENANCE.md` refer to the
original Mesa/application layout; they are not current dependencies or valid
relative links in this extracted package.

The current `shared:aws` package owns credential resolution, SigV4, S3 and SES
service behavior in `credentials.odin`, `s3.odin` and `ses.odin`. It imports sibling
`files` for bounded profile reads and `surf` for outbound HTTP; it does not import
Mesa's private helpers or Saba. The optional `shared:saba/s3` adapter delegates to
AWS. Surf's legacy bounded curl-backed execution remains a separate transport
migration, not code owned or reimplemented by AWS.

Preserve this origin record, existing source notices and repository history when
copying or upgrading. This extraction/distribution work introduces no new license
for existing owned code. The [package README](README.md) documents its callable
ownership and offline provider seams; the parent
[Webtools distribution guide](../../docs/WEBTOOLS_DISTRIBUTION.md) records current
module owners, dependency closures and source/toolchain evidence.
