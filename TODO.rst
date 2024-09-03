pan-chainguard To Do List
=========================

- Split chain.py into separate programs for:

  + Intermediate certificate discovery
  + Certificate download

- Re-implement chain.py to use a tree.

- Enhance chain.py to provide a visual representation of the
  certificate hierarchy.

- Provide alternate certificate sources besides downloading from
  crt.sh.  For example, create a separate content git repository.

- Add automated tests; consider using Python unittest unit testing
  framework.

- Optimise XML API usage for increased performance; consider use
  of multi-config.

- Retry transient XML API errors when possible.
