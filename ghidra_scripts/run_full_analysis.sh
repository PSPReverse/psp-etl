#!/usr/bin/env bash
# run_full_analysis.sh — Apply the complete PSP analysis pipeline to a project folder.
#
# Runs all analysis scripts in the correct order:
#   1. ApplyZen2MemoryMap  — Add SRAM/SMN/MMIO/ROM memory regions
#   2. RelinkArchiveTypes  — Link types to centralized .gdt archives
#   3. TransferLabelsFuzzy — Transfer labels from a reference program (if provided)
#   4. SmartRename         — Auto-name functions via SVC IDs + strings
#   5. InferPrintf         — Identify printf-like functions
#   6. AnnotateMMIO        — Label MMIO register accesses
#   7. RecoverStringXrefs  — Recover missing string cross-references
#   8. LabelMailboxHandlers — Find and label mailbox dispatch + handlers
#
# Usage:
#   ./ghidra_scripts/run_full_analysis.sh <folder> [--reference <source_path>]
#
# Example:
#   ./ghidra_scripts/run_full_analysis.sh zen2_test
#   ./ghidra_scripts/run_full_analysis.sh zen2_test --reference /zen5/PSP_FW_TRUSTED_OS_v0.2B.0.49
#
# Environment:
#   GHIDRA_PROJECT  — path to Ghidra project dir (default: data/ghidra)
#   GHIDRA_NAME     — project name (default: psp-etl)
#   GDT_DIR         — path to .gdt archives (default: data/ghidra_archives)

set -euo pipefail

FOLDER="${1:?Usage: $0 <folder> [--gen <gen>] [--platform <platform>] [--reference <source_path>]}"
shift

REFERENCE=""
GEN="zen2"
PLATFORM="ryzen"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reference) REFERENCE="$2"; shift 2 ;;
        --gen) GEN="$2"; shift 2 ;;
        --platform) PLATFORM="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

PROJECT_DIR="${GHIDRA_PROJECT:-$(pwd)/data/ghidra}"
PROJECT_NAME="${GHIDRA_NAME:-psp-etl}"
GDT_DIR="${GDT_DIR:-$(pwd)/data/ghidra_archives}"
SCRIPTS="$(pwd)/ghidra_scripts"
ANALYZE="ghidra-analyzeHeadless"

echo "=== PSP Full Analysis Pipeline ==="
echo "  Project: ${PROJECT_DIR}/${PROJECT_NAME}/${FOLDER}"
echo "  Generation: ${GEN} / ${PLATFORM}"
echo "  Archives: ${GDT_DIR}"
echo "  Reference: ${REFERENCE:-none}"
echo ""

# Step 1: Memory Map
echo "[1/8] Applying ${GEN}/${PLATFORM} memory map..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/setup" \
    -postScript ApplyPspMemoryMap.java "$GEN" "$PLATFORM" \
    2>&1 | grep -E "(Applied|ERROR)" || true
echo ""

# Step 2: Type Linking
echo "[2/8] Linking types to archives..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/project" \
    -postScript RelinkArchiveTypes.java "$GDT_DIR" \
    2>&1 | grep -E "(Summary|relinked|ERROR)" || true
echo ""

# Step 3: Label Transfer (optional)
if [[ -n "$REFERENCE" ]]; then
    echo "[3/8] Transferring labels from reference (fuzzy)..."
    $ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
        -recursive -process -noanalysis \
        -scriptPath "$SCRIPTS/transfer" \
        -postScript TransferLabelsFuzzy.java "$REFERENCE" \
        2>&1 | grep -E "(Transfer Summary|Exact|Instruction|String|ERROR)" || true
    echo ""

    echo "[3b/8] Transferring labels (loose)..."
    $ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
        -recursive -process -noanalysis \
        -scriptPath "$SCRIPTS/transfer" \
        -postScript TransferLabelsLoose.java "$REFERENCE" \
        2>&1 | grep -E "(Transfer Summary|Mnemonic|Prologue|Call|ERROR)" || true
    echo ""
else
    echo "[3/8] Skipping label transfer (no --reference provided)"
    echo ""
fi

# Step 4: Smart Rename
echo "[4/8] Auto-naming functions (SVC + strings)..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/analysis" \
    -postScript SmartRename.java \
    2>&1 | grep -E "(SmartRename Summary|SVC-named|String-named|ERROR)" || true
echo ""

# Step 5: Infer Printf
echo "[5/8] Identifying printf-like functions..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/analysis" \
    -postScript InferPrintf.java \
    2>&1 | grep -E "(Printf Summary|candidates|confirmed|ERROR)" || true
echo ""

# Step 6: Annotate MMIO
echo "[6/8] Annotating MMIO accesses..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/analysis" \
    -postScript AnnotateMMIO.java \
    2>&1 | grep -E "(MMIO Access Summary|Total annotated|Mailbox writes|ERROR)" || true
echo ""

# Step 7: Recover String Xrefs
echo "[7/8] Recovering string cross-references..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/analysis" \
    -postScript RecoverStringXrefs.java \
    2>&1 | grep -E "(Recovery Summary|Literal pool|MOVW|Pointer|ERROR)" || true
echo ""

# Step 8: Label Mailbox Handlers
echo "[8/8] Labeling mailbox dispatch handlers..."
$ANALYZE "$PROJECT_DIR" "${PROJECT_NAME}/${FOLDER}" \
    -recursive -process -noanalysis \
    -scriptPath "$SCRIPTS/analysis" \
    -postScript LabelMailboxHandlers.java \
    2>&1 | grep -E "(Dispatch function|Commands found|Handlers labeled|LABELED|ERROR)" || true
echo ""

echo "=== Pipeline Complete ==="
