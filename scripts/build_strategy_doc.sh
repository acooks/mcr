#!/bin/bash
# This script combines, formats, and converts the strategic markdown documents
# into a single, coherent HTML file with embedded SVG diagrams.

set -e # Exit immediately if a command exits with a non-zero status.

# Define the source directory and output files
STRATEGY_DIR="strategy"
DRAFT_MD_SOURCE="${STRATEGY_DIR}/STRATEGY_DRAFT.md"
MD_FOR_PANDOC="${STRATEGY_DIR}/PANDOC_INPUT.md"
FINAL_HTML="${STRATEGY_DIR}/STRATEGY.html"
SOURCE_FILES=(
    "${STRATEGY_DIR}/EXECUTIVE_SUMMARY.md"
    "${STRATEGY_DIR}/PROBLEM_SPACE_ANALYSIS.md"
    "${STRATEGY_DIR}/USER_PERSONAS.md"
    "${STRATEGY_DIR}/COMPETITIVE_LANDSCAPE.md"
)

# --- Cleanup function to remove temporary files ---
cleanup() {
    echo "Cleaning up temporary files..."
    rm -f "${STRATEGY_DIR}"/*.mmd "${MD_FOR_PANDOC}"
}
trap cleanup EXIT

# 1. Concatenate the source files into a single draft markdown file.
echo "Combining markdown files into ${DRAFT_MD_SOURCE}..."
cat "${SOURCE_FILES[@]}" > "${DRAFT_MD_SOURCE}"

# 2. Format the combined markdown file for consistency.
echo "Formatting ${DRAFT_MD_SOURCE} with Prettier..."
prettier --write "${DRAFT_MD_SOURCE}"

# 3. Process Mermaid diagrams
echo "Processing Mermaid diagrams..."
cp "${DRAFT_MD_SOURCE}" "${MD_FOR_PANDOC}"
DIAGRAM_INDEX=0
# Use awk to find and replace mermaid blocks
awk '
  BEGIN { diagram_index = 0; in_mermaid = 0; }
  /```mermaid/ {
    in_mermaid = 1;
    diagram_index++;
    diagram_file = "'"${STRATEGY_DIR}"'/diagram_" diagram_index ".mmd";
    print "![Strategic Diagram " diagram_index "](./diagram_" diagram_index ".svg)" > "'"${MD_FOR_PANDOC}"'"
    next;
  }
  /```/ {
    if (in_mermaid) {
      in_mermaid = 0;
      next;
    }
  }
  { 
    if (in_mermaid) {
      print $0 >> diagram_file;
    } else {
      print $0 >> "'"${MD_FOR_PANDOC}"'"
    }
  }
' "${DRAFT_MD_SOURCE}"

# This is a bit of a hack to get awk to work line-by-line on the file and replace in place.
# We overwrite the original pandoc input file with the awk output.
mv "${MD_FOR_PANDOC}" "${MD_FOR_PANDOC}.tmp"
mv "${MD_FOR_PANDOC}.tmp" "${MD_FOR_PANDOC}"


# Now, generate SVG for each .mmd file
for mmd_file in "${STRATEGY_DIR}"/*.mmd; do
    if [ -f "$mmd_file" ]; then
        SVG_FILE="${mmd_file%.mmd}.svg"
        echo "Generating SVG for ${mmd_file} -> ${SVG_FILE}"
        mmdc -i "$mmd_file" -o "$SVG_FILE" -b transparent
    fi
done

# 4. Convert the modified markdown file into a standalone HTML document.
echo "Converting to HTML at ${FINAL_HTML}..."
pandoc "${MD_FOR_PANDOC}" \
    -o "${FINAL_HTML}" \
    --standalone \
    --toc \
    --metadata title="MCR Strategic Analysis"

echo "Done. The final document is available at ${FINAL_HTML}"