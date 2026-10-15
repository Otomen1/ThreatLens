"use client";
import { useOwnerSession } from "@/components/OwnerSessionProvider";
export function useSessionIdentity() {
  return useOwnerSession().userId;
}
