v0.106.3

- BackupJsonExporter.export_frames now sanitizes certain information, such as some keys, as a defense-in-depth measure.
  It also now returns (per-frame) validator errors if a disappearing message or view-once attachment is included.

- SVRB: resurrect support for Nitro enclaves (no enclaves yet trusted)
