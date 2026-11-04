import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ApiError } from "../lib/api";
import { ErrorBox, JsonView, SeverityBadge } from "./ui";

describe("ui", () => {
  it("shows severity as text, not only color", () => {
    render(<SeverityBadge severity="high" />);
    expect(screen.getByText("high").className).toContain("sev-high");
  });

  it("renders hostile text as text", () => {
    const { container } = render(<JsonView value={{ user: "<script>alert(1)</script>" }} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
  });

  it("shows API error codes, field errors and request IDs", () => {
    const error = new ApiError(422, "VALIDATION_ERROR", "The request is invalid.", {
      errors: [{ loc: ["query", "start"], msg: "timestamp must include a timezone offset" }],
    }, "req_1");
    render(<ErrorBox error={error} />);
    expect(screen.getByRole("alert").textContent).toContain("VALIDATION_ERROR");
    expect(screen.getByText(/start: timestamp must include/)).toBeTruthy();
    expect(screen.getByText(/req_1/)).toBeTruthy();
  });
});
