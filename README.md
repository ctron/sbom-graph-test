# Testing Apache AGE

The goal is to get a better understanding of SBOMs (SPDX SBOMs) in the context of graph databases. Not using Apache AGE.

## Fetching an initial dataset

This needs to be done at least once.

```bash
sbom download https://access.redhat.com/security/data/sbom/beta -k https://access.redhat.com/security/data/97f5eac4.txt#77E79ABE93673533ED09EBE2DCE3823597F5EAC4 -d data/current 
```

## Starting services (PostgreSQL)

```bash
podman-compose up
```

## Ingesting data

```bash
cargo run
```

You can use `RUST_LOG=info` to get more info.

> [!IMPORTANT]  
> Re-running the ingesting will drop and re-create the graph instance.

### Ingesting a subset

You can use `-p prefix` or `--prefix prefix` to limit the files ingested. The prefix is checked again the start of
the file name.

### SPDX license expressions

> [!NOTE]  
> The ingesting process will replace all invalid license expressions with `NOASSERTION`. It will also store
> all files with a `.processed` extension to speed up re-running the process.

## Playing with the data

Then you can play with the data. See [`test.sql`](test.sql) for some examples.
