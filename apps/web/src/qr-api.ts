import { apiRequest } from "./auth-api";

export type QrChallengeCreated = {
  challenge_id: string;
  qr_payload: string;
  subscription_token: string;
  verification_code: string;
  qr_expires_at: string;
  poll_after_ms: number;
};

export type QrSnapshot = {
  challenge_id: string;
  status: "CREATED" | "SCANNED" | "APPROVED" | "EXCHANGED" | "REJECTED" | "EXPIRED" | "CANCELLED";
  lock_version: number;
  qr_expires_at: string;
  approval_expires_at: string | null;
};

export type QrDetails = {
  challenge_id: string;
  status: string;
  lock_version: number;
  requested_ua_summary: string | null;
  requested_ip: string | null;
  created_at: string;
  qr_expires_at: string;
  code_verified: boolean;
};

export const qrApi = {
  create() {
    return apiRequest<QrChallengeCreated>("/v1/qr-login/challenges", { method: "POST" });
  },
  bootstrap(qrToken: string) {
    return apiRequest<void>("/v1/qr-login/bootstrap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ qr_token: qrToken }),
    });
  },
  async scan() {
    const csrf = await apiRequest<{ csrf_token: string }>("/v1/auth/csrf");
    return apiRequest<{ challenge_id: string; lock_version: number }>("/v1/qr-login/scan", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf.csrf_token },
    });
  },
  details(id: string) {
    return apiRequest<QrDetails>(`/v1/qr-login/challenges/${id}`);
  },
  async verifyCode(id: string, verificationCode: string, lockVersion: number) {
    const csrf = await apiRequest<{ csrf_token: string }>("/v1/auth/csrf");
    return apiRequest<{ challenge_id: string; lock_version: number }>(`/v1/qr-login/challenges/${id}/verify-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf.csrf_token },
      body: JSON.stringify({ verification_code: verificationCode, lock_version: lockVersion }),
    });
  },
  async decide(id: string, decision: "approve" | "reject", lockVersion: number) {
    const csrf = await apiRequest<{ csrf_token: string }>("/v1/auth/csrf");
    return apiRequest<QrSnapshot>(`/v1/qr-login/challenges/${id}/${decision}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf.csrf_token },
      body: JSON.stringify({ lock_version: lockVersion }),
    });
  },
  status(id: string, subscriptionToken: string) {
    return apiRequest<QrSnapshot>(`/v1/qr-login/challenges/${id}/status`, {
      headers: { Authorization: `Bearer ${subscriptionToken}` },
    });
  },
  exchange(id: string, subscriptionToken: string) {
    return apiRequest<void>("/v1/qr-login/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_id: id, subscription_token: subscriptionToken }),
    });
  },
  cancel(id: string, subscriptionToken: string) {
    return apiRequest<void>(`/v1/qr-login/challenges/${id}/cancel`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subscription_token: subscriptionToken }),
    });
  },
};
