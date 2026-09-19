import { describe, expect, it } from "vitest";

import { generatePassword } from "./passwordGenerator";

describe("generatePassword", () => {
  it("uses the requested length and every selected character type", () => {
    const password = generatePassword({
      length: 24,
      lowercase: true,
      uppercase: true,
      numbers: true,
      symbols: true,
    });
    expect(password).toHaveLength(24);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*_+=?\-]/);
  });

  it("clamps length to the safe 12–64 range", () => {
    const options = { lowercase: true, uppercase: false, numbers: false, symbols: false };
    expect(generatePassword({ ...options, length: 2 })).toHaveLength(12);
    expect(generatePassword({ ...options, length: 200 })).toHaveLength(64);
  });

  it("requires at least one character type", () => {
    expect(() => generatePassword({
      length: 20,
      lowercase: false,
      uppercase: false,
      numbers: false,
      symbols: false,
    })).toThrow("Select at least one character type.");
  });
});
