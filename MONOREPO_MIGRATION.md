# Monorepo Migration

This document records the initial FloraCore monorepo migration so the old branch layout remains traceable.

## Imported source snapshots

The first monorepo import used these source commits:

| Component | Historical branch | Imported commit |
| --- | --- | --- |
| Firmware | `firmware` | `f3db03f7d145982d8f1ff0a39105b1097faa0781` |
| FloraOS web/backend | `website` | `4a47aa1dc648fc36486886c9fec596b15b5fb8f6` |
| Project/docs base | `main` | `0d1ad169f0fe24addaa086b33db5b77c871e4bc6` |

The import commit has all three lines of development as parents so the historical commits remain reachable in the Git graph.

## New locations

```text
old firmware branch root  -> firmware/
old website branch root   -> web/
main project docs         -> repository root + docs/
```

## Validation checklist

Before merging the migration to `main`:

- [ ] confirm every firmware source file exists under `firmware/`
- [ ] confirm every public website/backend source file exists under `web/`
- [ ] confirm no production secret or database was introduced
- [ ] run `idf.py build` from `firmware/`
- [ ] create a clean Python environment from `web/requirements.txt`
- [ ] run the FloraOS regression tests from `web/`
- [ ] review README, architecture, security, and contribution links
- [ ] add monorepo-aware CI
- [ ] verify GitHub Linguist reports sensible languages
- [ ] keep historical `firmware` and `website` branches until after migration stabilizes

## Historical branches

The `firmware` and `website` branches should not be deleted as part of the initial migration. They are useful references for the pre-monorepo project state.

New feature work should move to normal topic branches from `main` after the migration is merged.
