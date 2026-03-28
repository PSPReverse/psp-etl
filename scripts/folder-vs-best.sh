#!/usr/bin/env bash
# Compare the best folder for a generation against the global per-type best.
# Shows which components you're sacrificing by picking one coherent image
# instead of cherrypicking the best blob for each type.
#
# Usage: ./scripts/folder-vs-best.sh [gen]
# Example: ./scripts/folder-vs-best.sh zen2
set -euo pipefail

GEN=${1:-zen2}

folder=$(psp-etl best --folder --gen "$GEN" --format json)
global=$(psp-etl best          --gen "$GEN" --format json)

jq -n \
  --argjson folder "$folder" \
  --argjson global "$global" \
  '($global | map({(.type_id): .score}) | add) as $best |
   $folder[0].components[] |
   {
     type_id,
     type_name,
     folder_score: (.score // 0),
     best_score:   ($best[.type_id] // 0),
     delta:        (($best[.type_id] // 0) - (.score // 0))
   }' \
| jq -s 'sort_by(-.delta)'
