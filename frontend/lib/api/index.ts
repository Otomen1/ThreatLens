// Typed client for the ThreatLens API.
//
// Detection and enrichment live entirely in the backend; this module only
// transports requests and types responses. The base URL is configurable so the
// same build works same-origin (default) or against a separately-hosted backend.
//
// One subsystem module per file (mirroring backend/src/threatlens/api/routes/);
// this barrel re-exports all of them so existing `from "@/lib/api"` / `from
// "./api"` imports keep working unchanged.

export * from "./client";
export * from "./investigation";
export * from "./ai";
export * from "./detection";
export * from "./detectionKnowledge";
export * from "./exposure";
export * from "./identity";
export * from "./correlation";
export * from "./system";
