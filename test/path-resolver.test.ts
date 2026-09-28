import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { afterEach, describe, expect, it } from "vitest";

import { assessPathResource } from "../src/guardrails/path-policy.js";
import { classifyResource } from "../src/opencode/coordinator.js";
import {
  canonicalizeNearestExisting,
  FILESYSTEM_PATH_RESOLVER,
} from "../src/opencode/path-resolver.js";

const temporaryRoots: string[] = [];

function makeWorkspace(): Readonly<{ root: string; project: string }> {
  const root = mkdtempSync(join(tmpdir(), "opencode-jev-path-"));
  const project = join(root, "project");
  mkdirSync(project);
  temporaryRoots.push(root);
  return { root, project };
}

afterEach(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root !== undefined) rmSync(root, { recursive: true, force: true });
  }
});

describe("production path resolver", () => {
  it("normalizes parent traversal before classifying project scope", () => {
    const { root, project } = makeWorkspace();
    const outside = join(root, "outside.txt");
    writeFileSync(outside, "outside");
    const disguised = join(project, "..", "outside.txt");

    expect(canonicalizeNearestExisting(disguised)).toBe(realpathSync.native(outside));
    expect(classifyResource(disguised, "read", project).scope).toBe("external");
  });

  it("resolves a project symlink before applying secret policy", () => {
    const { root, project } = makeWorkspace();
    const secret = join(root, "credentials");
    const link = join(project, "apparently-safe.txt");
    writeFileSync(secret, "test-only");
    symlinkSync(secret, link);

    const finding = assessPathResource(link, {
      boundaries: { projectRoot: project },
      resolver: FILESYSTEM_PATH_RESOLVER,
      actionCategory: "read",
    });
    expect(finding.scope).toBe("secret");
    expect(finding.signals).toContain("secret_access");
    expect(finding.hardDeny).toBe(true);
    expect(classifyResource(link, "read", project).scope).toBe("secret");
  });

  it("resolves the nearest existing ancestor for a new destination", () => {
    const { project } = makeWorkspace();
    const future = join(project, "new", "deep", "file.txt");

    expect(canonicalizeNearestExisting(future)).toBe(future);
    expect(classifyResource(future, "edit", project).scope).toBe("project");
  });

  it("keeps paths inside a project opened through a symlink in project scope", () => {
    const { root } = makeWorkspace();
    const actualProject = join(root, "actual-project");
    const linkedProject = join(root, "linked-project");
    mkdirSync(actualProject);
    symlinkSync(actualProject, linkedProject);
    const file = join(actualProject, "notes.txt");
    writeFileSync(file, "notes");

    const throughLink = join(linkedProject, "notes.txt");
    expect(classifyResource(throughLink, "read", linkedProject).scope).toBe("project");
  });

  it("fails closed for malformed or relative resolver input", () => {
    expect(canonicalizeNearestExisting("relative/path")).toBeUndefined();
    expect(canonicalizeNearestExisting("/tmp/bad\u0000path")).toBeUndefined();
  });
});
