#!/usr/bin/env node
/**
 * Validate Mermaid diagrams in markdown files.
 *
 * This script finds all Mermaid code blocks in markdown files and validates
 * them using the @mermaid-js/mermaid-cli tool (mmdc).
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

/**
 * Find all markdown files, excluding node_modules, .git, and target.
 */
function findMarkdownFiles(dir, excludeDirs = ['node_modules', '.git', 'target']) {
  let results = [];

  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!excludeDirs.includes(entry.name)) {
        results = results.concat(findMarkdownFiles(fullPath, excludeDirs));
      }
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      results.push(fullPath);
    }
  }

  return results;
}

/**
 * Extract all Mermaid code blocks from a markdown file.
 *
 * Returns an array of { lineNumber, content } objects.
 */
function extractMermaidBlocks(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const blocks = [];

  let i = 0;
  while (i < lines.length) {
    if (lines[i].trim() === '```mermaid') {
      const startLine = i + 1; // 1-indexed for display
      const diagramLines = [];
      i++;

      // Collect lines until we hit the closing ```
      while (i < lines.length && lines[i].trim() !== '```') {
        diagramLines.push(lines[i]);
        i++;
      }

      if (diagramLines.length > 0) {
        blocks.push({
          lineNumber: startLine + 1,
          content: diagramLines.join('\n')
        });
      }
    }
    i++;
  }

  return blocks;
}

/**
 * Validate a Mermaid diagram using mmdc.
 *
 * Returns { valid: boolean, error: string }
 */
function validateDiagram(diagramContent) {
  const tempDir = os.tmpdir();
  const tempInput = path.join(tempDir, `mermaid_${Date.now()}_${Math.random().toString(36).substring(7)}.mmd`);
  const tempOutput = path.join(tempDir, `mermaid_${Date.now()}_${Math.random().toString(36).substring(7)}.svg`);

  try {
    // Write diagram to temp file
    fs.writeFileSync(tempInput, diagramContent);

    // Run mmdc validation
    execSync(`npx -y mmdc -i "${tempInput}" -o "${tempOutput}"`, {
      encoding: 'utf8',
      stdio: 'pipe'
    });

    return { valid: true, error: '' };

  } catch (error) {
    const errorMsg = error.stdout || error.stderr || error.message;
    return { valid: false, error: errorMsg };

  } finally {
    // Cleanup temp files
    try { fs.unlinkSync(tempInput); } catch {}
    try { fs.unlinkSync(tempOutput); } catch {}
  }
}

/**
 * Main validation logic.
 */
function main() {
  console.log('--- Validating Mermaid Diagrams ---');

  // Check if npm is available
  try {
    execSync('npm --version', { stdio: 'pipe' });
  } catch (error) {
    console.error('Error: npm is not installed.');
    process.exit(1);
  }

  const rootDir = process.cwd();
  const mdFiles = findMarkdownFiles(rootDir);

  // Filter to only files that contain mermaid blocks
  const filesWithMermaid = mdFiles.filter(file => {
    const content = fs.readFileSync(file, 'utf8');
    return content.includes('```mermaid');
  });

  if (filesWithMermaid.length === 0) {
    console.log('No Mermaid diagrams found.');
    process.exit(0);
  }

  let totalErrors = 0;

  for (const mdFile of filesWithMermaid) {
    const relPath = path.relative(rootDir, mdFile);
    console.log(`Validating: ./${relPath}`);

    const blocks = extractMermaidBlocks(mdFile);
    console.log(`  Found ${blocks.length} diagram(s)`);

    for (const block of blocks) {
      const result = validateDiagram(block.content);

      if (result.valid) {
        console.log(`  ✓ Diagram at line ${block.lineNumber} valid`);
      } else {
        console.error(`  ✗ Invalid Mermaid syntax at line ${block.lineNumber} in ${relPath}`);
        if (result.error) {
          const shortError = result.error.substring(0, 200);
          console.error(`    Error: ${shortError}`);
        }
        totalErrors++;
      }
    }

    if (blocks.length > 0) {
      console.log(`  ✅ All diagrams in ${relPath} validated`);
    }
  }

  if (totalErrors > 0) {
    console.error(`\n❌ Found ${totalErrors} invalid diagram(s)`);
    process.exit(1);
  }

  console.log('\n✅ All Mermaid diagrams validated');
  process.exit(0);
}

main();
