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

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    parent: { type: "string" },
    version: { type: "string" },
    tag: { type: "string" },
    sbom: { type: "string", multiple: true },
    "oci-sbom": { type: "string", multiple: true },
    project: { type: "string", multiple: true },
  },
});

const command = positionals[0];

function usage() {
  console.error(
    `Usage:
  node scripts/dependency-track.mjs upload --parent <parent> --version <version> [--sbom <name>=<path> ...] [--oci-sbom <name>=<image> ...]
  node scripts/dependency-track.mjs tag --parent <parent> --tag <tag> --version <version> [--project <name> ...]
  node scripts/dependency-track.mjs analyze [--parent <parent>] --version <version> --project <name> [...]`
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

async function ensureParentProject(parentName, version) {
  const existing = await lookupProject(parentName, version, true);
  if (existing) {
    if (!existing.active) {
      await sendJson("PATCH", `/api/v1/project/${existing.uuid}`, { active: true });
    }
    return existing.uuid;
  }
  console.log(`Creating parent project ${parentName} (${version})...`);
  const created = await sendJson("PUT", "/api/v1/project", {
    name: parentName,
    version,
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

async function uploadBom(parent, parentUuid, version, rawName, rawBom) {
  const projectName = qualifyName(parent, rawName);
  const bomContent = toCycloneDxIfSpdx(rawBom);

  console.log(`Uploading BOM for ${projectName} (${version}) under ${parent} (${version})...`);
  const base64Bom = Buffer.from(bomContent).toString("base64");
  const uploadRes = await sendJson("PUT", "/api/v1/bom", {
    autoCreate: true,
    parentUUID: parentUuid,
    projectName,
    projectVersion: version,
    bom: base64Bom,
  });

  const childUuid = uploadRes?.projectUuid || (await lookupProject(projectName, version)).uuid;
  await sendJson("PATCH", `/api/v1/project/${childUuid}`, {
    active: true,
    parent: { uuid: parentUuid },
  });

  await waitForBomProcessing(uploadRes?.token, projectName);
}

async function uploadCommand() {
  const { parent, version, sbom = [], "oci-sbom": ociSbom = [] } = values;
  if (!parent || !version || (!sbom.length && !ociSbom.length)) {
    usage();
  }

  const parentUuid = await ensureParentProject(parent, version);

  for (const entry of sbom) {
    const [rawName, bomPath] = parseEntry("--sbom", entry);
    if (!fs.existsSync(bomPath) || !fs.statSync(bomPath).isFile()) {
      throw new Error(`BOM file not found: ${bomPath}`);
    }
    await uploadBom(parent, parentUuid, version, rawName, fs.readFileSync(bomPath, "utf8"));
  }

  for (const entry of ociSbom) {
    const [rawName, image] = parseEntry("--oci-sbom", entry);
    await uploadBom(parent, parentUuid, version, rawName, downloadOciSbom(image));
  }

  console.log(`All BOMs uploaded and processed for version ${version}.`);
}

async function tagCommand() {
  const { parent, tag, version, project = [] } = values;
  if (!tag || !version || (!parent && !project.length)) {
    usage();
  }

  const targetNames = new Set();
  if (parent) {
    targetNames.add(parent);
  }
  for (const p of project) {
    targetNames.add(qualifyName(parent, p));
  }

  console.log(`Removing tag '${tag}' from older versions...`);
  const resp = await request("GET", `/api/v1/project/tag/${encodeURIComponent(tag)}?pageSize=1000&pageNumber=1`);
  const taggedProjects = resp.ok ? await resp.json() : [];

  for (const proj of taggedProjects) {
    if (targetNames.has(proj.name) && proj.version !== version) {
      console.log(`Untagging '${tag}' from ${proj.name} (${proj.version})...`);
      const fullOldProj = await sendJson("GET", `/api/v1/project/${proj.uuid}`);
      const tags = (fullOldProj.tags || []).filter((t) => t.name !== tag);
      await sendJson("PATCH", `/api/v1/project/${proj.uuid}`, { tags });
    }
  }

  for (const projName of targetNames) {
    console.log(`Tagging ${projName} (${version}) with '${tag}'...`);
    const proj = await lookupProject(projName, version);
    const existingTags = proj.tags || [];
    const hasTag = existingTags.some((t) => t.name === tag);
    if (!hasTag || !proj.active) {
      await sendJson("PATCH", `/api/v1/project/${proj.uuid}`, {
        active: true,
        tags: hasTag ? existingTags : [...existingTags, { name: tag }],
      });
    }
  }

  if (parent) {
    const parentVersions =
      (await sendJson(
        "GET",
        `/api/v1/project?name=${encodeURIComponent(parent)}&excludeInactive=true&pageSize=1000&pageNumber=1`
      )) || [];

    for (const parentProj of parentVersions) {
      const children =
        (await sendJson(
          "GET",
          `/api/v1/project/${parentProj.uuid}/children?excludeInactive=true&pageSize=1000&pageNumber=1`
        )) || [];

      let hasActiveChildren = false;
      for (const child of children) {
        if (!child.tags?.length) {
          console.log(`Deactivating untagged project ${child.name} (${child.version})...`);
          await sendJson("PATCH", `/api/v1/project/${child.uuid}`, { active: false });
        } else {
          hasActiveChildren = true;
        }
      }

      if (!parentProj.tags?.length && !hasActiveChildren) {
        console.log(`Deactivating untagged project ${parentProj.name} (${parentProj.version})...`);
        await sendJson("PATCH", `/api/v1/project/${parentProj.uuid}`, { active: false });
      }
    }
  }

  console.log(`Tag '${tag}' applied to version ${version}.`);
}

async function analyzeCommand() {
  const { parent, version, project } = values;
  if (!version || !project?.length) {
    usage();
  }

  let hasFailures = false;

  for (const rawName of project) {
    const projectName = qualifyName(parent, rawName);
    const proj = await lookupProject(projectName, version);
    const violations = (await sendJson("GET", `/api/v1/violation/project/${proj.uuid}?suppressed=false`)) || [];

    const failed = violations.filter((v) => v.policyCondition?.policy?.violationState === "FAIL");
    const warns = violations.filter((v) => v.policyCondition?.policy?.violationState === "WARN");
    const uiLink = `${dtrackUrl}/projects/${proj.uuid}`;

    if (failed.length > 0) {
      hasFailures = true;
      console.error(`\n[FAIL] ${projectName} (${version}): ${failed.length} failed policy violation(s) (${warns.length} warning(s))`);
      console.error(`  UI: ${uiLink}`);
      for (const v of failed) {
        const policyName = v.policyCondition?.policy?.name || "Unknown Policy";
        const comp = v.component ? `${v.component.name}${v.component.version ? `@${v.component.version}` : ""}` : "Unknown Component";
        const cond = v.policyCondition ? `${v.policyCondition.subject} ${v.policyCondition.operator} ${v.policyCondition.value}` : "";
        console.error(`  - [${v.type}] ${policyName}: ${comp} (${cond})`);
      }
    } else {
      console.log(`[PASS] ${projectName} (${version}): 0 failed violations (${warns.length} warning(s)) -> ${uiLink}`);
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
    case "tag":
      await tagCommand();
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
