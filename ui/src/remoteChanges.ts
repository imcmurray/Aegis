/**
 * Remote change log helpers (D22). Pure and DOM-free: they only format the
 * non-secret change records the delegate returns.
 */

import type { FieldChange, RemoteChange, RemoteChangeKind } from "./messages";

export function remoteChangePillLabel(
  kind: RemoteChangeKind | undefined,
): "New" | "Updated" | null {
  if (kind === "added") return "New";
  if (kind === "modified") return "Updated";
  return null;
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

function isoDate(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

export function formatRelativeTime(ts: number, nowSecs: number): string {
  const d = nowSecs - ts;
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  if (d < 30 * 86400) return `${plural(Math.floor(d / 86400), "day")} ago`;
  return isoDate(ts);
}

const FIELD_LABELS: Record<string, string> = {
  name: "Name",
  username: "Username",
  folder: "Folder",
};

function asText(v: string | string[] | undefined): string {
  if (v === undefined) return "";
  return Array.isArray(v) ? v.join(", ") : v;
}

function asList(v: string | string[] | undefined): string[] {
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function shown(v: string | string[] | undefined, emptyLabel: string): string {
  const t = asText(v);
  return t === "" ? emptyLabel : t;
}

function describeList(label: string, fc: FieldChange): string {
  const oldL = asList(fc.old);
  const newL = asList(fc.new);
  const added = newL.filter((x) => !oldL.includes(x));
  const removed = oldL.filter((x) => !newL.includes(x));
  const parts: string[] = [];
  if (added.length) parts.push(`added ${added.join(", ")}`);
  if (removed.length) parts.push(`removed ${removed.join(", ")}`);
  if (!parts.length) return `${label} changed`;
  return `${label}: ${parts.join(", ")}`;
}

export function describeFieldChange(fc: FieldChange): string {
  const f = fc.field;
  if (f === "password") {
    return "Password changed (previous password is in Password history)";
  }
  if (f === "notes") return "Notes changed";
  if (f === "totp") return "Authenticator (TOTP) changed";
  if (f === "urls") return describeList("URLs", fc);
  if (f === "tags") return describeList("Labels", fc);
  if (f === "name" || f === "username" || f === "folder") {
    const empty = f === "folder" ? "(no folder)" : "(empty)";
    return `${FIELD_LABELS[f]}: ${shown(fc.old, empty)} → ${shown(fc.new, empty)}`;
  }
  if (f.startsWith("custom:")) {
    const label = fc.label && fc.label !== "" ? fc.label : "Custom field";
    if (fc.old === undefined && fc.new === undefined) {
      return `Hidden field “${label}” changed`;
    }
    if (fc.old === undefined) return `${label}: added ${shown(fc.new, "(empty)")}`;
    if (fc.new === undefined) return `${label}: removed`;
    return `${label}: ${shown(fc.old, "(empty)")} → ${shown(fc.new, "(empty)")}`;
  }
  return `${f} changed`;
}

export function remoteChangePanelTitle(rc: RemoteChange, nowSecs: number): string {
  return `Changed on another device · ${formatRelativeTime(rc.changed_at, nowSecs)}`;
}

export function describeRemoteChange(rc: RemoteChange): string[] {
  if (rc.kind === "added") return ["Added on another device"];
  const fields = rc.fields ?? [];
  return fields.map(describeFieldChange);
}

export function removedNoticeText(entries: RemoteChange[]): string {
  const names = entries.map((e) => e.entry_name ?? "(unnamed entry)");
  return `Removed on another device: ${names.join(", ")}`;
}

export function syncChangedSuffix(n: number | undefined): string {
  if (!n || n <= 0) return "";
  return n === 1
    ? " · 1 entry updated from another device"
    : ` · ${n} entries updated from another device`;
}
