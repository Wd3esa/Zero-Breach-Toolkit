# Adding a reader

`zbtriage/readers.py` is the shared registry for the source CLI, single-file
builder, platform selection, `--describe` coverage and entry-point test stubs.
It contains trusted built-ins only. Collections and reports cannot install or
select arbitrary Python code.

1. Add `zbtriage/modules/example.py` with a unique `NAME` and
   `run(ctx) -> ModuleResult`. Publish the active result as `ctx.partial` before
   reading records so cancellation preserves evidence.
2. Add one `ReaderSpec` to `READER_SPECS` in `readers.py`: result name, module
   filename without extension, bundle suffix, host platforms, modes, catalogue
   and any optional helper filenames. Descriptor order determines execution and
   build order. The optional `patterns` switch remains explicitly opt-in.
3. Include every reported check name and the reader's limitations in its
   catalogue. `contract.CHECK_CATALOGUE` is derived from this metadata; do not
   maintain a second entry there. Prefix internal symbols uniquely because the
   single-file build shares one namespace.
4. Add bounded synthetic fixtures proving evidence meaning, malformed-input
   recovery, source preservation and source/bundle parity. The registry-wide
   `stub_registered_readers` helper automatically isolates new modules in
   entry-point tests. An end-to-end fixture must explicitly opt a real reader
   back in and point every discovery root at its temporary data.
5. Run the tests and release check, then update the coverage documentation.

`desktop` mode applies the descriptor's host-platform filter. `targeted` mode
only selects readers that implement exclusive handling of `ctx.targets`, and
may analyse copied artifacts from another operating system. `android` and
`ios` modes operate on the supplied phone collection and never select host
readers. Reader import failures, invalid result types and runtime failures are
reported as gaps by the shared dispatcher. Per-record recovery remains the
reader's responsibility.

Do not follow executable paths found in artifacts. Read-only analysis must not
execute commands, mount registry hives, resolve links, elevate privileges or
download parser dependencies. Enforce byte, record, traversal and decoding
limits before allocating or decompressing untrusted data. Missing optional
artifacts are inapplicable; unreadable expected or present artifacts are gaps.
Neither case is permission to claim that records were parsed when they were not.

The registry deliberately does not load external plugins. Adding a trusted
reader requires reviewing source, registering it and rebuilding the bundle.
