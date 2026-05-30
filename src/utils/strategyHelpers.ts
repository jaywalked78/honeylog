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
