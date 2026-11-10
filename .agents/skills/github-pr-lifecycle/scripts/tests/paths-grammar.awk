# The trigger-block `paths:` grammar shared by the agent-skill shell suites.
#
# tests/pr-checks.bash and tests/agent-skills-workflow.bash both need the
# `paths:` list of ONE trigger (`push` or `pull_request`). That program used to
# exist as two copies, which could drift: one suite would keep passing while
# the other failed on the same workflow edit. The grammar lives here once and
# both suites load it with `-f`.
#
# Invoked as:
#
#   awk -v want=<trigger> -v mode=paths|has -f paths-grammar.awk <workflow>
#
#   want -- the trigger key to scope to: `push` or `pull_request`.
#   mode -- `paths` prints the list entries, one per line, before the caller's
#           normalisation (it strips quotes and sorts); `has` prints `yes` when
#           the trigger block carries a `paths:` key at all, and nothing
#           otherwise. `has` exists because a `paths:` key that parses to an
#           empty list is a parser regression, not a workflow with no filter.
#
# `mode` is validated in `BEGIN`, before any rule runs: it is a two-valued
# switch, and a typo must fail loudly rather than fall through to `paths` and
# print a plausible list. That is the same reason the boundaries below are
# pinned rather than inferred -- a silent wrong answer is the failure mode this
# program exists to prevent. The two `-v` assignments precede `-f`, the POSIX
# invocation order, so both are bound when `BEGIN` runs.
#
# RULE ORDER IS THE CONTRACT, and it is fixed: every rule is only correct
# because each earlier rule already had the first chance at the line.
#
#   1. the comment rule;
#   2. the trigger key that opens the block;
#   3. the two block exits (column 0, then the trigger's own indent);
#   4. the `paths:` key that opens the list;
#   5. the entry rules (blank line, list entry, everything else ends the list).
#
# Each rule below carries the reason it must sit where it does. Read them in
# order: they are one argument, not five independent notes.
#
# The block ends at the next key at or above the trigger's own indent,
# INCLUDING column 0. That is what stops a missing `paths:` under `push:` from
# making this program walk into `pull_request:` -- or into a top-level section
# such as `jobs:` -- and print that block's entries, a false PASS. Each
# boundary below was verified by manual mutation testing out of tree; the
# assertions in both suites exist to keep them true.
#
# Only a `paths:` key at exactly four spaces opens the list, so a `branches:`
# or `filters:` sub-list of the same trigger is never collected. A trailing
# comment on the trigger key or on the `paths:` key is tolerated, so a
# commented key does not silently return an empty list.
#
# The list itself ends at the first line that is neither a list entry, a blank
# line, nor a comment.

# The program's first block, and the only one that runs before any input is
# read. Validating `mode` here is the whole point: a typo such as `hass` must
# not fall through to `paths` and print a plausible list. `inblock`/`inpaths`
# are initialised so no rule reads an uninitialised variable -- POSIX defines
# them as 0, but `gawk --lint` is right to object.
BEGIN {
  if (mode != "paths" && mode != "has") {
    print "paths-grammar.awk: mode must be paths or has, got '" mode "'" > "/dev/stderr"
    exit 2
  }
  inblock = 0
  inpaths = 0
}

# A comment line carries no YAML structure: `#` is not part of the
# `^  <trigger>:` or `^    paths:` prefixes this grammar matches, so a comment
# can never open a block -- and must not terminate one. Hoisted to the first
# rule so a comment at column 0 or at the block indent cannot end the scan.
# Exactly one comment rule per program.
/^[[:space:]]*#/ { next }

# The trigger that scopes the search. Only `push` and `pull_request` are ever
# asked for, and only at two spaces: a `branches:` entry or a job-level key of
# the same name is not a trigger.
$0 ~ ("^  " want ":([[:space:]]*#.*)?[[:space:]]*$") { inblock = 1; next }

# The two block exits. Column 0 first, then the trigger's own indent: either
# one means the trigger block has ended, so a later `paths:` cannot be read as
# this trigger's.
inblock && /^[^ ]/ { exit }
inblock && /^  [^ ]/ { exit }

# The `paths:` opener. In `paths` mode it starts collecting entries; in `has`
# mode the presence of the key is the whole answer.
inblock && /^    paths:([[:space:]]*#.*)?[[:space:]]*$/ {
  if (mode == "has") {
    print "yes"
    exit
  }
  inpaths = 1
  next
}

inpaths && /^[[:space:]]*$/ { next }
inpaths && /^[[:space:]]*-[[:space:]]*/ {
  line = $0
  sub(/^[[:space:]]*-[[:space:]]*/, "", line)
  sub(/[[:space:]]+#.*$/, "", line)
  sub(/[[:space:]]+$/, "", line)
  print line
  next
}
inpaths { exit }
