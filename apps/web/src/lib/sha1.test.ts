import { describe, expect, it } from "vitest";
import { kAnonymitySplit, sha1Hex } from "./sha1";

describe("sha1Hex", () => {
  it("matches the published test vectors", () => {
    expect(sha1Hex("")).toBe("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
    expect(sha1Hex("abc")).toBe("A9993E364706816ABA3E25717850C26C9CD0D89D");
    expect(sha1Hex("password")).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    expect(sha1Hex("The quick brown fox jumps over the lazy dog")).toBe("2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12");
  });
  it("handles multi-block and non-ASCII input", () => {
    expect(sha1Hex("a".repeat(1000))).toBe("291E9A6C66994949B57BA5E650361E98FC36B1BA");
    expect(sha1Hex("pässwörd")).toMatch(/^[0-9A-F]{40}$/);
  });
  it("sends only the first five characters", () => {
    const { prefix, suffix } = kAnonymitySplit(sha1Hex("password"));
    expect(prefix).toBe("5BAA6");
    expect(suffix).toBe("1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    expect(prefix.length).toBe(5);
  });
});
