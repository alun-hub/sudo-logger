const text = '[1.0, "o", "\\u001b[24;80H"]';
const reCUP = /(?:\\u001b|\\x1b|\x1b)\[(\d+);(\d+)[Hf]/gi;
let match;
while ((match = reCUP.exec(text)) !== null) {
  console.log(match[1], match[2]);
}
