# generated-configs/

Output of `schema-helper` (see the main README): suggested configs for
ipfixcol2 (`config.xml`) and ClickHouse (`schema.sql`), derived from the
templates an exporter actually sends.

IMPORTANT: nothing here is ever copied into `../../configs/` automatically.
Always review it by hand and merge it with what is already in `configs/`
(column names, types, partitioning), so a generic output does not overwrite
the tuned setup.
