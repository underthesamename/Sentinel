export type User = {
  id: string;
  email: string;
};

export type Session = {
  id: string;
  idle_expires_at: string;
  absolute_expires_at: string;
};

export type SessionResponse = {
  user: User;
  session: Session;
};

type ProblemDetails = {
  code?: string;
  correlation_id?: string;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly correlationId?: string,
  ) {
    super(code);
  }
}

export async function apiRequest<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;

  try {
    response = await fetch(path, {
      credentials: "include",
      ...options,
      headers: {
        Accept: "application/json",
        ...options?.headers,
      },
    });
  } catch {
    throw new ApiError(0, "NETWORK_UNAVAILABLE");
  }

  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as ProblemDetails;
    throw new ApiError(
      response.status,
      problem.code ?? "UNEXPECTED_RESPONSE",
      problem.correlation_id,
    );
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

function credentialsBody(email: string, password: string): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  };
}

export const authApi = {
  register(email: string, password: string) {
    return apiRequest<User>("/v1/auth/register", credentialsBody(email, password));
  },

  login(email: string, password: string) {
    return apiRequest<SessionResponse>("/v1/auth/login", credentialsBody(email, password));
  },

  currentSession() {
    return apiRequest<SessionResponse>("/v1/auth/me");
  },

  async logout() {
    const csrf = await apiRequest<{ csrf_token: string }>("/v1/auth/csrf");
    await apiRequest<void>("/v1/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf.csrf_token },
    });
  },

  csrf() {
    return apiRequest<{ csrf_token: string }>("/v1/auth/csrf");
  },
};
