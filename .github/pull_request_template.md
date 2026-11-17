## What and why

## How it was tested

- [ ] `python -m pytest -q guard/tests panel/tests`
- [ ] fresh install in a container (`ci/fresh_install.sh`), if the installer changed
- [ ] `ci/db_restore.sh`, if backups or restore tests changed
- [ ] docs and `CHANGELOG.md` updated
- [ ] no secret printed, logged or mailed; shell values quoted; HTML escaped
