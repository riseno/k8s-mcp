# Stability and deprecation

From 1.0, k8s-mcp's public surface is stable: an MCP client, a prompt or a script written
against 1.0 keeps working on every 1.x release.

## What is stable

- **Tools:** each tool's name, its toolset and tier (read, write or destructive), its
  arguments' names, the JSON types and enum values they accept, and which arguments are
  required.
- **Prompts and resources:** prompt names and arguments, resource URIs and the resource
  template.
- **Rule ids:** every finding id, such as `pod.oom.container`. An id is never renamed or reused
  for a different problem.
- **The Envelope:** the top-level fields of every tool's structured output (`summary`,
  `findings`, `items`, `truncated`, `omitted`, `next`, `context`, `namespace`,
  `untrusted_fields`, `sections`) and their meaning ([output.md](output.md)).

The 1.0 surface is recorded in [`surface-v1.json`](surface-v1.json). A test compares every build
against it and fails on anything that removes or changes what that file lists.

## What may change in 1.x

- New tools, prompts, resources and rule ids.
- New optional arguments, wider argument types and new enum values.
- New Envelope fields, new columns in `items`, and new sections.
- Wording: summaries, finding titles, explanations, fixes, descriptions and error messages. Match
  on rule ids and fields, never on text.
- Which findings a cluster produces and their order, severity and confidence: rules improve.
- Defaults that make k8s-mcp safer, such as tighter redaction or a new refusal.

## Deprecation

In 1.x nothing listed under "What is stable" is removed or renamed, and no argument becomes
required. Something that should go is deprecated instead:

1. Its description (or its rule's title) says it is deprecated and what replaces it.
2. The CHANGELOG lists it under **Deprecated** in the release that deprecates it.
3. It keeps working until 2.0, the only release that may remove it.

Security fixes are the one exception: if keeping a behaviour would expose data or allow a change
the safety model forbids, a 1.x release may refuse it. The CHANGELOG says so.
