#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { parseArgs } from "node:util";

const apiKey = process.env.DEPENDENCY_TRACK_API_KEY;
if (!apiKey || !apiKey.trim()) {
  console.log("DEPENDENCY_TRACK_API_KEY is not set; skipping Dependency-Track step.");
  process.exit(0);
}

const dtrackUrl = (process.env.DEPENDENCY_TRACK_URL?.trim() || "https://dtrack.dsiag.ch").replace(/\/+$/, "");

const VALID_ENVS = new Set(["preview", "prod"]);

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    parent: { type: "string" },
    env: { type: "string" },
    sbom: { type: "string", multiple: true },
    "oci-sbom": { type: "string", multiple: true },
    project: { type: "string", multiple: true },
  },
});

const command = positionals[0];

function usage() {
  console.error(
    `Usage:
  dtrack upload --parent <parent> --env <preview|prod> [--sbom <name>=<path> ...] [--oci-sbom <name>=<image> ...]
  dtrack analyze [--parent <parent>] --env <preview|prod> --project <name> [...]`
  );
  process.exit(1);
}

function qualifyName(parent, name) {
  if (!parent || name === parent || name.startsWith(`${parent}-`)) {
    return name;
  }
  return `${parent}-${name}`;
}

async function request(method, path, body) {
  const headers = { "X-Api-Key": apiKey };
  const options = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  return fetch(`${dtrackUrl}${path}`, options);
}

async function sendJson(method, path, body) {
  const resp = await request(method, path, body);
  const text = await resp.text();
  if (resp.status >= 400) {
    throw new Error(`${method} ${path} failed (HTTP ${resp.status}): ${text}`);
  }
  return text ? JSON.parse(text) : null;
}

async function lookupProject(name, version, allowNotFound = false) {
  const path = `/api/v1/project/lookup?name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`;
  const resp = await request("GET", path);
  if (allowNotFound && resp.status === 404) {
    return null;
  }
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`Lookup failed for ${name} (${version}): HTTP ${resp.status} ${text}`);
  }
  return JSON.parse(text);
}

async function ensureParentProject(parentName, env) {
  const existing = await lookupProject(parentName, env, true);
  if (existing) {
    if (!existing.active) {
      await sendJson("PATCH", `/api/v1/project/${existing.uuid}`, { active: true });
    }
    return existing.uuid;
  }
  console.log(`Creating parent project ${parentName} (${env})...`);
  const created = await sendJson("PUT", "/api/v1/project", {
    name: parentName,
    version: env,
    classifier: "APPLICATION",
    collectionLogic: "AGGREGATE_DIRECT_CHILDREN",
    active: true,
  });
  return created.uuid;
}

async function waitForBomProcessing(token, projectName) {
  if (!token) return;
  const maxAttempts = 60;
  for (let i = 0; i < maxAttempts; i++) {
    const status = await sendJson("GET", `/api/v1/bom/token/${encodeURIComponent(token)}`);
    if (!status?.processing) {
      return;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.warn(`Warning: Timed out waiting for BOM processing on ${projectName}.`);
}

function parseEntry(flag, entry) {
  const eqIdx = entry.indexOf("=");
  if (eqIdx <= 0) {
    throw new Error(`Invalid ${flag} argument '${entry}', expected <name>=<value>`);
  }
  return [entry.slice(0, eqIdx), entry.slice(eqIdx + 1)];
}

export function toCycloneDxIfSpdx(rawBom) {
  let doc;
  try {
    doc = JSON.parse(rawBom);
  } catch {
    return rawBom;
  }
  if (!doc?.spdxVersion) {
    return rawBom;
  }

  const isHermeto = (pkg) =>
    (pkg.annotations || []).some((a) => JSON.stringify(a).toLowerCase().includes("hermeto"));
  const removedIds = new Set();

  if (Array.isArray(doc.packages)) {
    doc.packages = doc.packages.filter((pkg) => {
      if (isHermeto(pkg)) {
        removedIds.add(pkg.SPDXID);
        return false;
      }
      return true;
    });
  }
  if (Array.isArray(doc.relationships)) {
    doc.relationships = doc.relationships.filter(
      (r) => !removedIds.has(r.spdxElementId) && !removedIds.has(r.relatedSpdxElement)
    );
  }
  if (Array.isArray(doc.documentDescribes)) {
    doc.documentDescribes = doc.documentDescribes.filter((id) => !removedIds.has(id));
  }

  console.log(`Converting SPDX (${doc.spdxVersion}, removed ${removedIds.size} Hermeto package(s)) to CycloneDX v1.5...`);
  return execFileSync(
    "cyclonedx",
    ["convert", "--input-format", "spdxjson", "--output-format", "json", "--output-version", "v1_5"],
    { input: JSON.stringify(doc), encoding: "utf8", maxBuffer: 50 * 1024 * 1024 }
  );
}

export function downloadOciSbom(image) {
  console.log(`Downloading linux/amd64 OCI SBOM for ${image}...`);
  return execFileSync("cosign", ["download", "sbom", "--platform", "linux/amd64", image], {
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  });
}

async function uploadBom(parent, parentUuid, env, rawName, rawBom) {
  const projectName = qualifyName(parent, rawName);
  const bomContent = toCycloneDxIfSpdx(rawBom);

  console.log(`Uploading BOM for ${projectName} (${env}) under ${parent} (${env})...`);
  const base64Bom = Buffer.from(bomContent).toString("base64");
  const uploadRes = await sendJson("PUT", "/api/v1/bom", {
    autoCreate: true,
    parentUUID: parentUuid,
    projectName,
    projectVersion: env,
    bom: base64Bom,
  });

  const childUuid = uploadRes?.projectUuid || (await lookupProject(projectName, env)).uuid;
  await sendJson("PATCH", `/api/v1/project/${childUuid}`, {
    active: true,
    parent: { uuid: parentUuid },
  });

  await waitForBomProcessing(uploadRes?.token, projectName);
}

async function uploadCommand() {
  const { parent, env, sbom = [], "oci-sbom": ociSbom = [] } = values;
  if (!parent || !VALID_ENVS.has(env) || (!sbom.length && !ociSbom.length)) {
    usage();
  }

  const parentUuid = await ensureParentProject(parent, env);

  for (const entry of sbom) {
    const [rawName, bomPath] = parseEntry("--sbom", entry);
    if (!fs.existsSync(bomPath) || !fs.statSync(bomPath).isFile()) {
      throw new Error(`BOM file not found: ${bomPath}`);
    }
    await uploadBom(parent, parentUuid, env, rawName, fs.readFileSync(bomPath, "utf8"));
  }

  for (const entry of ociSbom) {
    const [rawName, image] = parseEntry("--oci-sbom", entry);
    await uploadBom(parent, parentUuid, env, rawName, downloadOciSbom(image));
  }

  console.log(`All BOMs uploaded and processed for environment ${env}.`);
}

async function analyzeCommand() {
  const { parent, env, project } = values;
  if (!VALID_ENVS.has(env) || !project?.length) {
    usage();
  }

  let hasFailures = false;

  for (const rawName of project) {
    const projectName = qualifyName(parent, rawName);
    const proj = await lookupProject(projectName, env);
    const violations = (await sendJson("GET", `/api/v1/violation/project/${proj.uuid}?suppressed=false`)) || [];

    const failed = violations.filter((v) => v.policyCondition?.policy?.violationState === "FAIL");
    const warns = violations.filter((v) => v.policyCondition?.policy?.violationState === "WARN");
    const uiLink = `${dtrackUrl}/projects/${proj.uuid}`;

    if (failed.length > 0) {
      hasFailures = true;
      console.error(`\n[FAIL] ${projectName} (${env}): ${failed.length} failed policy violation(s) (${warns.length} warning(s))`);
      console.error(`  UI: ${uiLink}`);
      for (const v of failed) {
        const policyName = v.policyCondition?.policy?.name || "Unknown Policy";
        const comp = v.component ? `${v.component.name}${v.component.version ? `@${v.component.version}` : ""}` : "Unknown Component";
        const cond = v.policyCondition ? `${v.policyCondition.subject} ${v.policyCondition.operator} ${v.policyCondition.value}` : "";
        console.error(`  - [${v.type}] ${policyName}: ${comp} (${cond})`);
      }
    } else {
      console.log(`[PASS] ${projectName} (${env}): 0 failed violations (${warns.length} warning(s)) -> ${uiLink}`);
    }
  }

  if (hasFailures) {
    process.exit(1);
  }
}

try {
  switch (command) {
    case "upload":
      await uploadCommand();
      break;
    case "analyze":
      await analyzeCommand();
      break;
    default:
      usage();
  }
} catch (err) {
  console.error(err.message || err);
  process.exit(1);
}
