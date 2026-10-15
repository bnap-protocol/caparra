# Embedded data

`registry.json` is the registry export of the spec repository
(`bnap/registry/generated/registry.json`, made by `registry/validate.py
--export`), copied byte for byte at bnap commit `ce73bc8` (`node/release`, 2026-10-15), export
digest `06cd086aab52775673424886462f8b4940cb62d28404e4475c15b2b9a755994f`.

The wallet reads every scheme's binding class, use model, refund property and
property vector from it, never from a server or a plug. Replace the file with a
newer export to update the wallet's view of the registry; the test
`registry::tests::the_embedded_export_is_the_one_named_here` pins the digest.
