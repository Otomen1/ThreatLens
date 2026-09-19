const LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
const UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const NUMBERS = "23456789";
const SYMBOLS = "!@#$%^&*_-+=?";

export interface PasswordGeneratorOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

function randomIndex(max: number): number {
  const limit = Math.floor(256 / max) * max;
  const bytes = new Uint8Array(1);
  do crypto.getRandomValues(bytes); while (bytes[0] >= limit);
  return bytes[0] % max;
}

function choose(characters: string): string {
  return characters[randomIndex(characters.length)];
}

export function generatePassword(options: PasswordGeneratorOptions): string {
  const length = Math.max(12, Math.min(64, Math.trunc(options.length)));
  const groups = [
    options.lowercase ? LOWERCASE : "",
    options.uppercase ? UPPERCASE : "",
    options.numbers ? NUMBERS : "",
    options.symbols ? SYMBOLS : "",
  ].filter(Boolean);
  if (groups.length === 0) throw new Error("Select at least one character type.");
  if (length < groups.length) throw new Error("Password length is too short.");

  const all = groups.join("");
  const result = groups.map(choose);
  while (result.length < length) result.push(choose(all));
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapWith = randomIndex(index + 1);
    [result[index], result[swapWith]] = [result[swapWith], result[index]];
  }
  return result.join("");
}
