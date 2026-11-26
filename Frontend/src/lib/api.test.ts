import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  api,
  buildQuery,
  formatApiError,
  onUnauthorized,
  setAccessToken,
} from "./api";

const fetchMock = vi.fn<typeof fetch>();

function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  onUnauthorized(null);
  setAccessToken(null);
});

describe("buildQuery", () => {
  it("skips empty values and repeats arrays", () => {
    expect(
      buildQuery({ page: 1, q: "", status: undefined, ports: [22, 443], ok: false }),
    ).toBe("?page=1&ports=22&ports=443&ok=false");
  });

  it("returns no question mark for empty params", () => {
    expect(buildQuery({})).toBe("");
    expect(buildQuery()).toBe("");
  });
});

describe("api client", () => {
  it("sends the bearer token and parses success JSON", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(jsonResponse({ id: 7 }));
    setAccessToken("token-123");

    await expect(api.assessments.get(7)).resolves.toEqual({ id: 7 });
    const init = fetchMock.mock.calls[0]?.[1];
    expect((init?.headers as Record<string, string>).Authorization).toBe(
      "Bearer token-123",
    );
  });

  it("maps the error envelope to ApiError", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "scope_violation",
            message: "Target is outside scope",
            details: { reasons: ["host is not whitelisted"] },
          },
        },
        403,
      ),
    );

    const error = await api.scope
      .check(1, { target: "http://x", tool: "curl" })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 403,
      code: "scope_violation",
      details: { reasons: ["host is not whitelisted"] },
    });
    expect(formatApiError(error)).toContain("host is not whitelisted");
  });

  it("surfaces validation details without parsing messages", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "validation_error",
            message: "Request validation failed",
            details: [
              {
                loc: ["body", "title"],
                msg: "String should have at least 1 character",
                type: "string_too_short",
              },
            ],
          },
        },
        422,
      ),
    );

    const error = await api.findings
      .create(1, { title: "", severity: "low" })
      .catch((caught: unknown) => caught);
    expect(formatApiError(error)).toBe(
      "Request validation failed: title: String should have at least 1 character",
    );
  });

  it("calls the unauthorized handler on protected 401s only", async () => {
    vi.stubGlobal("fetch", fetchMock);
    const handler = vi.fn();
    onUnauthorized(handler);
    setAccessToken("expired");

    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { error: { code: "invalid_token", message: "Token expired" } },
        401,
      ),
    );
    await api.auth.me().catch(() => undefined);
    expect(handler).toHaveBeenCalledOnce();

    handler.mockClear();
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { error: { code: "invalid_credentials", message: "Bad login" } },
        401,
      ),
    );
    await api.auth
      .login({ email: "a@b.test", password: "wrong" })
      .catch(() => undefined);
    expect(handler).not.toHaveBeenCalled();
  });

  it("reports retry seconds for login throttling", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      jsonResponse(
        { error: { code: "too_many_attempts", message: "Too many attempts" } },
        429,
        { "Retry-After": "120" },
      ),
    );

    const error = await api.auth
      .login({ email: "a@b.test", password: "x" })
      .catch((caught: unknown) => caught);
    expect(formatApiError(error)).toContain("Try again in 120s");
  });

  it("does not duplicate the API prefix for backend download URLs", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(
      new Response("evidence", {
        status: 200,
        headers: {
          "Content-Disposition": 'attachment; filename="shot.png"',
        },
      }),
    );

    const result = await api.findings.evidence.download(
      "/api/v1/evidence/5/download",
    );
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toMatch(/\/api\/v1\/evidence\/5\/download$/);
    expect(url).not.toContain("/api/v1/api/v1");
    expect(result.filename).toBe("shot.png");
  });
});
