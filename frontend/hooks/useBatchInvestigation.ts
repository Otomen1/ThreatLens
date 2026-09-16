"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import {
  investigate,
  previewInvestigationBatch,
  type BatchItemStatus,
  type BatchPreviewResponse,
  type Entity,
  type InvestigationResponse,
  type InvestigationOptions,
} from "@/lib/api";
import { clearBatchSession, loadBatchSession, saveBatchSession, type StoredBatchSession } from "@/lib/batchSession";

export interface BatchRow {
  entity: Entity;
  state: BatchItemStatus;
  investigation: InvestigationResponse | null;
  error: string | null;
  errorCode: string | null;
  retryable: boolean;
  selected: boolean;
  savedId: string | null;
}

const DEADLINE_MS = 45_000;
const CONCURRENCY = 4;

function initialRow(entity: Entity): BatchRow {
  return { entity, state: "queued", investigation: null, error: null, errorCode: null, retryable: false, selected: false, savedId: null };
}

export function useBatchInvestigation() {
  const [preview, setPreview] = useState<BatchPreviewResponse | null>(null);
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [previewing, setPreviewing] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rowsRef = useRef<BatchRow[]>([]);
  const runId = useRef(0);
  const previewId = useRef(0);
  const previewController = useRef<AbortController | null>(null);
  const optionsRef = useRef<InvestigationOptions>({ scanMode: "standard" });
  const [recoverable, setRecoverable] = useState<StoredBatchSession | null>(null);
  const controllers = useRef(new Set<AbortController>());

  const cancel = useCallback(() => {
    runId.current += 1;
    previewId.current += 1;
    previewController.current?.abort();
    previewController.current = null;
    controllers.current.forEach((controller) => controller.abort());
    controllers.current.clear();
    setRows((current) => current.map((row) => row.state === "queued" || row.state === "running" ? { ...row, state: "cancelled", error: "Cancelled.", errorCode: "cancelled", retryable: true } : row));
    setRunning(false);
  }, []);

  useEffect(() => () => {
    runId.current += 1;
    previewId.current += 1;
    previewController.current?.abort();
    controllers.current.forEach((controller) => controller.abort());
  }, []);

  useEffect(() => { rowsRef.current = rows; }, [rows]);

  const processTasks = useCallback(async (tasks: Array<{ index: number; entity: Entity }>) => {
    const activeRun = ++runId.current;
    setRunning(true);
    let cursor = 0;
    async function worker() {
      while (activeRun === runId.current) {
        const position = cursor++;
        const task = tasks[position];
        if (!task) return;
        const { index, entity } = task;
        setRows((current) => current.map((row, rowIndex) => rowIndex === index ? { ...row, state: "running", error: null, errorCode: null } : row));
        const controller = new AbortController();
        controllers.current.add(controller);
        let timedOut = false;
        const timeout = window.setTimeout(() => { timedOut = true; controller.abort(); }, DEADLINE_MS);
        try {
          const investigation = await investigate(entity.normalized_value, controller.signal, optionsRef.current);
          setRows((current) => current.map((row, rowIndex) => rowIndex === index ? { ...row, state: "completed", investigation, retryable: false, selected: true } : row));
        } catch (cause) {
          const aborted = cause instanceof DOMException && cause.name === "AbortError";
          const cancelled = aborted && !timedOut;
          const errorCode = timedOut ? "client_timeout" : cancelled ? "cancelled" : "investigation_failed";
          const message = timedOut ? "This IOC exceeded the 45-second deadline." : aborted ? "Cancelled." : "Investigation failed. You can retry this item.";
          setRows((current) => current.map((row, rowIndex) => rowIndex === index ? { ...row, state: cancelled ? "cancelled" : "failed", error: message, errorCode, retryable: true } : row));
        } finally {
          window.clearTimeout(timeout);
          controllers.current.delete(controller);
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, tasks.length) }, worker));
    if (activeRun === runId.current) setRunning(false);
  }, []);

  const start = useCallback(async (entities?: Entity[]) => {
    const selectedEntities = entities ?? preview?.entities ?? [];
    const nextRows = selectedEntities.map(initialRow);
    rowsRef.current = nextRows;
    setRows(nextRows);
    await processTasks(nextRows.map((row, index) => ({ index, entity: row.entity })));
  }, [preview, processTasks]);

  const prepare = useCallback(async (query: string, options: InvestigationOptions = {}) => {
    cancel();
    const requestId = ++previewId.current;
    const controller = new AbortController();
    previewController.current = controller;
    setPreviewing(true);
    setError(null);
    setPreview(null);
    setRows([]);
    try {
      optionsRef.current = options;
      const nextPreview = await previewInvestigationBatch(query, controller.signal, options);
      if (requestId !== previewId.current) return null;
      setPreview(nextPreview);
      if (!nextPreview.requires_confirmation) void start(nextPreview.entities);
      return nextPreview;
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === "AbortError") return null;
      setError(cause instanceof Error ? cause.message : "Could not preview this search.");
      return null;
    } finally {
      if (requestId === previewId.current) setPreviewing(false);
    }
  }, [cancel, start]);

  const retry = useCallback(async (indexes: number[]) => {
    setRows((current) => current.map((row, index) => indexes.includes(index) ? { ...row, state: "queued", error: null, errorCode: null } : row));
    await processTasks(indexes.flatMap((index) => {
      const entity = rowsRef.current[index]?.entity;
      return entity ? [{ index, entity }] : [];
    }));
  }, [processTasks]);

  useEffect(() => { void loadBatchSession().then(setRecoverable).catch(() => undefined); }, []);
  useEffect(() => {
    if (preview && rows.length > 1) void saveBatchSession({ savedAt: Date.now(), preview, rows, options: optionsRef.current });
  }, [preview, rows]);
  const resume = useCallback(() => {
    if (!recoverable) return;
    optionsRef.current = recoverable.options;
    setPreview(recoverable.preview); setRows(recoverable.rows); setRecoverable(null);
  }, [recoverable]);
  const discardRecovery = useCallback(() => { setRecoverable(null); void clearBatchSession(); }, []);
  const clear = useCallback(() => { cancel(); setPreview(null); setRows([]); setError(null); void clearBatchSession(); }, [cancel]);
  return { preview, setPreview, rows, setRows, previewing, running, error, prepare, start, retry, cancel, clear, recoverable, resume, discardRecovery };
}
