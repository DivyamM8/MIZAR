import { describe, expect, it } from "vitest";

import { withQuery } from "./api";
import { bytes, duration, timeBasis, utc } from "./format";

describe("utc", () => {
  it("always shows UTC with Z, never the browser's zone", () => {
    expect(utc("2026-10-29T06:30:01Z")).toBe("2026-10-29 06:30:01Z");
    expect(utc("2026-10-29T06:30:01.123456Z")).toBe("2026-10-29 06:30:01.123456Z");
    expect(utc("2026-10-29T06:30:01.000000Z")).toBe("2026-10-29 06:30:01Z");
    expect(utc("2026-10-29T12:00:01+05:30")).toBe("2026-10-29 06:30:01Z");
  });
  it("handles missing and invalid values", () => {
    expect(utc(null)).toBe("—");
    expect(utc("not a date")).toBe("not a date");
  });
});

describe("timeBasis", () => {
  it("labels how the UTC time was established", () => {
    expect(timeBasis("explicit").tone).toBe("ok");
    expect(timeBasis("format_defined_utc").label).toBe("UTC by format");
    expect(timeBasis("analyst_hint:Europe/Berlin")).toEqual({ label: "hint Europe/Berlin", tone: "hint" });
    expect(timeBasis("none").tone).toBe("none");
  });
});

describe("helpers", () => {
  it("formats sizes and durations", () => {
    expect(bytes(512)).toBe("512 B");
    expect(bytes(2 * 1024 ** 3)).toBe("2.0 GiB");
    expect(duration(30)).toBe("30s");
    expect(duration(3600)).toBe("1h");
  });
  it("builds query strings, dropping empty values", () => {
    expect(withQuery("/api/x", { a: "1", b: "", c: undefined, d: null, e: 0 })).toBe("/api/x?a=1&e=0");
    expect(withQuery("/api/x", { q: "a b&c" })).toBe("/api/x?q=a+b%26c");
    expect(withQuery("/api/x")).toBe("/api/x");
  });
});
