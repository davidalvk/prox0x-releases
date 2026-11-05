export type DiffLineKind = "same" | "add" | "remove";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  leftLine: number | null;
  rightLine: number | null;
}

export interface DiffResult {
  lines: DiffLine[];
  added: number;
  removed: number;
  truncated: boolean;
}

const MAX_CELLS = 4_000_000;

function count(lines: DiffLine[]): Pick<DiffResult, "added" | "removed"> {
  let added = 0;
  let removed = 0;
  for (const line of lines) {
    if (line.kind === "add") added += 1;
    if (line.kind === "remove") removed += 1;
  }
  return { added, removed };
}

function coarseDiff(left: string[], right: string[]): DiffResult {
  let prefix = 0;
  while (
    prefix < left.length &&
    prefix < right.length &&
    left[prefix] === right[prefix]
  ) {
    prefix += 1;
  }
  let suffix = 0;
  while (
    suffix < left.length - prefix &&
    suffix < right.length - prefix &&
    left[left.length - 1 - suffix] === right[right.length - 1 - suffix]
  ) {
    suffix += 1;
  }

  const lines: DiffLine[] = [];
  for (let index = 0; index < prefix; index += 1) {
    lines.push({
      kind: "same",
      text: left[index],
      leftLine: index + 1,
      rightLine: index + 1,
    });
  }
  const leftEnd = left.length - suffix;
  const rightEnd = right.length - suffix;
  for (let index = prefix; index < leftEnd; index += 1) {
    lines.push({
      kind: "remove",
      text: left[index],
      leftLine: index + 1,
      rightLine: null,
    });
  }
  for (let index = prefix; index < rightEnd; index += 1) {
    lines.push({
      kind: "add",
      text: right[index],
      leftLine: null,
      rightLine: index + 1,
    });
  }
  for (let offset = suffix; offset > 0; offset -= 1) {
    const leftIndex = left.length - offset;
    const rightIndex = right.length - offset;
    lines.push({
      kind: "same",
      text: left[leftIndex],
      leftLine: leftIndex + 1,
      rightLine: rightIndex + 1,
    });
  }
  return { lines, ...count(lines), truncated: true };
}

/** Diff por líneas con LCS; cae a prefijo/sufijo si el texto es enorme. */
export function diffLines(leftText: string, rightText: string): DiffResult {
  const left = leftText.split("\n");
  const right = rightText.split("\n");
  if (left.length * right.length > MAX_CELLS) {
    return coarseDiff(left, right);
  }

  const rows = left.length + 1;
  const columns = right.length + 1;
  const dp = Array.from({ length: rows }, () => new Uint32Array(columns));
  for (let i = left.length - 1; i >= 0; i -= 1) {
    for (let j = right.length - 1; j >= 0; j -= 1) {
      dp[i][j] =
        left[i] === right[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    if (left[i] === right[j]) {
      lines.push({
        kind: "same",
        text: left[i],
        leftLine: i + 1,
        rightLine: j + 1,
      });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      lines.push({
        kind: "remove",
        text: left[i],
        leftLine: i + 1,
        rightLine: null,
      });
      i += 1;
    } else {
      lines.push({
        kind: "add",
        text: right[j],
        leftLine: null,
        rightLine: j + 1,
      });
      j += 1;
    }
  }
  while (i < left.length) {
    lines.push({
      kind: "remove",
      text: left[i],
      leftLine: i + 1,
      rightLine: null,
    });
    i += 1;
  }
  while (j < right.length) {
    lines.push({
      kind: "add",
      text: right[j],
      leftLine: null,
      rightLine: j + 1,
    });
    j += 1;
  }

  return { lines, ...count(lines), truncated: false };
}
