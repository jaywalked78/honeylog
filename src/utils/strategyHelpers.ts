export function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export function subnet24(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error("Invalid IP address");
  }
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

// Jaccard similarity: the shared middle of a Venn diagram divided by both circles combined
// (items in both sets / distinct items across both). Two empty sets return 0: "no behavior" is not "identical behavior".
export function jaccard(firstSet: Set<string>, secondSet: Set<string>): number {
  if (firstSet.size === 0 && secondSet.size === 0) return 0;
  let intersection = 0;
  for (const item of firstSet) {
    if (secondSet.has(item)) intersection++;
  }
  const union = firstSet.size + secondSet.size - intersection;
  return union === 0 ? 0 : intersection / union;
}
