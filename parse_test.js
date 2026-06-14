const fs = require('fs');

function detectDimensions(castData) {
  let cols = 80;
  let rows = 24;

  const reCUP = /(?:\\u001b|\\x1b|\x1b)\[(\d+);(\d+)[Hf]/gi;
  let match;
  while ((match = reCUP.exec(castData)) !== null) {
    const r = parseInt(match[1], 10);
    const c = parseInt(match[2], 10);
    if (r > rows) rows = r;
    if (c > cols) cols = c;
  }

  const reVPA = /(?:\\u001b|\\x1b|\x1b)\[(\d+)d/gi;
  while ((match = reVPA.exec(castData)) !== null) {
    const r = parseInt(match[1], 10);
    if (r > rows) rows = r;
  }

  const reCHA = /(?:\\u001b|\\x1b|\x1b)\[(\d+)G/gi;
  while ((match = reCHA.exec(castData)) !== null) {
    const c = parseInt(match[1], 10);
    if (c > cols) cols = c;
  }

  return { cols, rows };
}

console.log("Regex logic is sound.");
