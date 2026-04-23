"use client";

import { AgentConfig, Phase } from "./types";

export type { Phase };

export interface ScanRecord {
  id: string;
  targetUrl: string;
  timestamp: string;
  config: AgentConfig;
  finalPhase: Phase;
  duration?: number;
}

const DB_NAME = "pentest-history";
const DB_VERSION = 1;
const STORE_RECORDS = "records";
const STORE_REPORTS = "reports";

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_RECORDS)) {
        db.createObjectStore(STORE_RECORDS, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_REPORTS)) {
        db.createObjectStore(STORE_REPORTS, { keyPath: "id" });
      }
    };
  });
}

export async function saveScanRecord(
  record: ScanRecord,
  report: string
): Promise<void> {
  const db = await openDB();
  const tx = db.transaction([STORE_RECORDS, STORE_REPORTS], "readwrite");
  await Promise.all([
    new Promise<void>((resolve, reject) => {
      const req = tx.objectStore(STORE_RECORDS).put(record);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    }),
    new Promise<void>((resolve, reject) => {
      const req = tx.objectStore(STORE_REPORTS).put({ id: record.id, report });
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    }),
  ]);
}

export async function getScanRecords(): Promise<ScanRecord[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RECORDS, "readonly");
    const req = tx.objectStore(STORE_RECORDS).getAll();
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const records: ScanRecord[] = (req.result as ScanRecord[]).sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      );
      resolve(records);
    };
  });
}

export async function getReportById(id: string): Promise<string> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_REPORTS, "readonly");
    const req = tx.objectStore(STORE_REPORTS).get(id);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve((req.result as { id: string; report: string })?.report ?? "");
  });
}

export async function deleteScanRecord(id: string): Promise<void> {
  const db = await openDB();
  const tx = db.transaction([STORE_RECORDS, STORE_REPORTS], "readwrite");
  await Promise.all([
    new Promise<void>((resolve, reject) => {
      const req = tx.objectStore(STORE_RECORDS).delete(id);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    }),
    new Promise<void>((resolve, reject) => {
      const req = tx.objectStore(STORE_REPORTS).delete(id);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve();
    }),
  ]);
}
