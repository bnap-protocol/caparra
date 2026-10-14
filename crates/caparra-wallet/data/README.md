# Embedded data

`registry.json` is the registry export of the spec repository
(`bnap/registry/generated/registry.json`, made by `registry/validate.py
--export`), copied byte for byte at bnap commit `00d0d24` (2026-10-13), export
digest `e133cf496b0463d36ccca71dd78bf3a6c6a21cf67ef31c0497996c0eb1de261c`.

The wallet reads every scheme's binding class, use model, refund property and
property vector from it, never from a server or a plug. Replace the file with a
newer export to update the wallet's view of the registry; the test
`registry::tests::the_embedded_export_is_the_one_named_here` pins the digest.
