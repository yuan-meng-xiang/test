import type { Config, Context } from "@netlify/functions";

declare const Netlify: {
  env: {
    get(name: string): string | undefined;
  };
};

const SESSION_COOKIE = "survey_admin_session";
const SESSION_SECONDS = 12 * 60 * 60;
const MAX_JSON_BYTES = 16 * 1024;
const QUESTION_IDS = Array.from({ length: 31 }, (_, index) => `Q${index + 1}`);

const QUESTION_TITLES: Record<string, string> = {
  Q1: "在过去12个月内，您是否曾通过以下任一渠道，就您所居住社区或所在城市的公共服务事项，向政府部门提交过建议、投诉、咨询或求助？",
  Q2: "那次您提交的事项属于以下哪种类型？",
  Q3: "在上述您提交过的所有事项中，是否至少有一次收到了来自政府部门的正式回复（包括电话、短信、书面回函或线上平台回复）？",
  Q4: "您反映的问题涉及哪个领域？",
  Q5: "在您得到的政府工作人员回复中，是否明确提到了具体的责任办理单位（如某具体部门）？",
  Q6: "该回复是否明确提到了反馈或办理的具体时间/期限？",
  Q7: "该回复是否明确说明了如果没有按时完成，会有后续追踪或问责后果？",
  Q8: "这条回复的篇幅/字数显得比较长。",
  Q9: "为了回复您的意见，政府工作人员付出了很大的努力。",
  Q10: "这条回复针对您提出的意见给出了很具体的说明。",
  Q11: "这条回复的语气非常有礼貌，态度友善。",
  Q12: "在现实生活中，政府工作人员给出这样的回复是非常真实、可信的。",
  Q13: "有了这样的回复，政府工作人员会对自己处理意见的结果负责。",
  Q14: "从回复来看，如果事情没办好，相关的政府部门或人员会受到追究。",
  Q15: "这条回复让您清楚了后续处理流程的具体步骤。",
  Q16: "整个处理过程对您而言是公开、明确的。",
  Q17: "您的这次反馈能够有效推动政府改善相关工作。",
  Q18: "像您这样的普通市民，有能力通过这种方式促进公共事务的解决。",
  Q19: "您对这次政府回复服务的整体质量感到满意。",
  Q20: "这种回复方式超出了您的预期。",
  Q21: "如果将来再有类似的征求意见活动，您仍然非常愿意参与。",
  Q22: "您会建议身边的朋友或家人也积极向政府反馈意见。",
  Q23: "基于这次回复，您认为本地政府能够真正解决民众关心的问题。",
  Q24: "您信任本地政府在做决策时会优先考虑公共利益。",
  Q25: "您的年龄是：",
  Q26: "您的性别：",
  Q27: "您的受教育程度：",
  Q28: "您目前的常住地属于：",
  Q29: "在本次调查之前，您是否有过向政府或社区提建议、投诉或咨询的经历？",
  Q30: "总的来说，您对政治或公共事务（如本地新闻、政府政策）的关注程度如何？",
  Q31: "在参与本次调查之前，您对本地政府（区/县或街道）的整体信任程度如何？",
};

type RpcJson = Record<string, unknown> | boolean | number | string | unknown[] | null;

function getEnv(name: string): string {
  const value = Netlify.env.get(name);
  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }
  return value;
}

function json(payload: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      ...securityHeaders(),
      ...headers,
    },
  });
}

function securityHeaders(): HeadersInit {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };
}

function clientKey(req: Request, context: Context): string {
  const forwarded = req.headers.get("x-forwarded-for") ?? "";
  const ip = forwarded.split(",", 1)[0].trim() || context.ip || "unknown";
  return ip;
}

function cookieValue(req: Request, name: string): string {
  const cookie = req.headers.get("cookie") ?? "";
  for (const part of cookie.split(";")) {
    const [rawName, ...valueParts] = part.trim().split("=");
    if (rawName === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }
  return "";
}

function sameOriginRequest(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (!origin) return true;
  return origin === new URL(req.url).origin;
}

async function readJsonBody(req: Request): Promise<Record<string, unknown>> {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength <= 0 || contentLength > MAX_JSON_BYTES) {
    throw new HttpError("request too large", 413);
  }
  try {
    const payload = await req.json();
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new HttpError("invalid json", 400);
    }
    return payload as Record<string, unknown>;
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError("invalid json", 400);
  }
}

async function rpc(functionName: string, args: Record<string, unknown> = {}): Promise<RpcJson> {
  const supabaseUrl = getEnv("SUPABASE_URL").replace(/\/+$/, "");
  const supabaseKey = getEnv("SUPABASE_PUBLISHABLE_KEY");
  const response = await fetch(`${supabaseUrl}/rest/v1/rpc/${functionName}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: supabaseKey,
      Authorization: `Bearer ${supabaseKey}`,
    },
    body: JSON.stringify(args),
  });

  const text = await response.text();
  const data = text ? JSON.parse(text) as RpcJson : null;
  if (!response.ok) {
    throw new HttpError("supabase request failed", response.status, data);
  }
  return data;
}

function errorStatus(error: unknown): number {
  if (error instanceof HttpError) return error.status;
  return 500;
}

function apiError(error: unknown): Response {
  if (error instanceof HttpError && error.details) {
    return json({ ok: false, error: error.message, details: error.details }, error.status);
  }
  return json({ ok: false, error: error instanceof Error ? error.message : "server error" }, errorStatus(error));
}

class HttpError extends Error {
  constructor(message: string, readonly status: number, readonly details?: unknown) {
    super(message);
  }
}

function isOkObject(data: RpcJson): data is Record<string, unknown> {
  return Boolean(data) && typeof data === "object" && !Array.isArray(data);
}

function statusForAppError(error: unknown): number {
  if (error === "unauthorized" || error === "invalid credentials") return 401;
  if (error === "too many attempts" || error === "too many submissions") return 429;
  return 400;
}

function sessionCookie(token: string, req: Request): string {
  const secure = new URL(req.url).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; SameSite=Strict${secure}`;
}

function expiredSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict`;
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function xlsBytes(rows: Record<string, unknown>[]): string {
  const headers = ["submitted_at", ...QUESTION_IDS];
  const questionHeader = ["提交时间", ...QUESTION_IDS.map((qid) => `${qid} ${QUESTION_TITLES[qid]}`)];
  const tableRows = [
    questionHeader,
    ...rows.map((row) => headers.map((header) => row[header] ?? "")),
  ];
  const body = tableRows.map((row) => (
    `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`
  )).join("");

  return `\ufeff<!doctype html>
<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
<head><meta charset="utf-8"></head>
<body><table border="1">${body}</table></body>
</html>`;
}

async function handleCount(): Promise<Response> {
  const count = await rpc("survey_response_count");
  return json({ count: Number(count) || 0 });
}

async function handleSubmit(req: Request, context: Context): Promise<Response> {
  if (!sameOriginRequest(req)) return json({ ok: false, error: "forbidden origin" }, 403);
  const payload = await readJsonBody(req);
  const data = await rpc("survey_submit_response", { payload, client_key: clientKey(req, context) });
  if (!isOkObject(data) || !data.ok) {
    return json(data, statusForAppError(isOkObject(data) ? data.error : ""));
  }
  return json(data, 201);
}

async function handleLogin(req: Request, context: Context): Promise<Response> {
  if (!sameOriginRequest(req)) return json({ ok: false, error: "forbidden origin" }, 403);
  const payload = await readJsonBody(req);
  const data = await rpc("survey_admin_login", {
    username: String(payload.username ?? ""),
    password: String(payload.password ?? ""),
    client_key: clientKey(req, context),
  });

  if (!isOkObject(data) || !data.ok || typeof data.token !== "string") {
    return json(data, statusForAppError(isOkObject(data) ? data.error : ""));
  }

  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(data.token, req) });
}

async function handleLogout(req: Request): Promise<Response> {
  if (!sameOriginRequest(req)) return json({ ok: false, error: "forbidden origin" }, 403);
  await rpc("survey_admin_logout", { token: cookieValue(req, SESSION_COOKIE) });
  return json({ ok: true }, 200, { "Set-Cookie": expiredSessionCookie() });
}

async function handleMe(req: Request): Promise<Response> {
  const data = await rpc("survey_admin_me", { token: cookieValue(req, SESSION_COOKIE) });
  return json(isOkObject(data) ? data : { authenticated: false });
}

async function handleClear(req: Request): Promise<Response> {
  if (!sameOriginRequest(req)) return json({ ok: false, error: "forbidden origin" }, 403);
  const data = await rpc("survey_admin_clear", { token: cookieValue(req, SESSION_COOKIE) });
  if (!isOkObject(data) || !data.ok) {
    return json(data, statusForAppError(isOkObject(data) ? data.error : ""));
  }
  return json(data);
}

async function handleExport(req: Request): Promise<Response> {
  const data = await rpc("survey_admin_export", { token: cookieValue(req, SESSION_COOKIE) });
  if (!isOkObject(data) || !data.ok) {
    return json(data, statusForAppError(isOkObject(data) ? data.error : ""));
  }
  const rows = Array.isArray(data.rows) ? data.rows as Record<string, unknown>[] : [];
  const filename = `anonymous_survey_results_${new Date().toISOString().replaceAll(/[-:]/g, "").slice(0, 15)}.xls`;

  return new Response(xlsBytes(rows), {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Type": "application/vnd.ms-excel; charset=utf-8",
      ...securityHeaders(),
    },
  });
}

export default async (req: Request, context: Context) => {
  try {
    const path = new URL(req.url).pathname;
    if (req.method === "GET" && path === "/api/count") return await handleCount();
    if (req.method === "GET" && path === "/api/me") return await handleMe(req);
    if (req.method === "GET" && path === "/api/export") return await handleExport(req);
    if (req.method === "POST" && path === "/api/login") return await handleLogin(req, context);
    if (req.method === "POST" && path === "/api/logout") return await handleLogout(req);
    if (req.method === "POST" && path === "/api/responses") return await handleSubmit(req, context);
    if (req.method === "DELETE" && path === "/api/responses") return await handleClear(req);
    return json({ ok: false, error: "not found" }, 404);
  } catch (error) {
    return apiError(error);
  }
};

export const config: Config = {
  path: "/api/*",
};
