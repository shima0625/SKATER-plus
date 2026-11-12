[日本語](https://github.com/shima0625/SKATER-plus/blob/v0.1.1/RELEASE_NOTES.ja.md)

> [!CAUTION]
> Most of this release's code and documentation was created with generative AI assistance.

- Batches SD writes and skips files that already match during reinstallation.
- Accelerates certificate verification, P-256 key exchange, and AES/GCM processing. In separate local tests on JPN hardware, certificate changes reduced connection setup time by 56–80%, and AES/GCM changes reduced transfer time by 13–24%.
- On JPN hardware, the startup update check took 1.62 seconds, patch application with SD writes took 5.19 seconds, and reapplying an unchanged patch took 2.42 seconds.
- Checks for stable releases and offers on-console CIA/3DSX patcher updates. Reopen the updated patcher to update an older browser patch.
- Preserves registered extra certificates during standard-layout browser patch updates.
- Updates USA/EUR compatibility to reflect community hardware reports for v0.1.0. TLS optimization retesting in those regions is pending; KOR hardware remains untested.

Assets: `skater-plus-patcher.cia` and `skater-plus-patcher.3dsx`.
