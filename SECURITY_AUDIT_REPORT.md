# Security Audit Report - Obsidian Periodic Notes Plugin

**Audit Date:** 2025-11-12
**Plugin Version:** 0.0.17
**Auditor:** Claude Code Security Analysis
**Repository:** obsidian-periodic-notes

---

## Executive Summary

This comprehensive security audit was conducted on the Obsidian Periodic Notes plugin, which has not been updated for several years. The audit identified **multiple critical and high-severity vulnerabilities** primarily in outdated dependencies, along with some code-level security concerns.

### Risk Level: **HIGH**

The application has significant security vulnerabilities that should be addressed urgently, particularly in its dependencies.

---

## Table of Contents

1. [Dependency Vulnerabilities](#dependency-vulnerabilities)
2. [Code Security Analysis](#code-security-analysis)
3. [Configuration Security](#configuration-security)
4. [Recommendations](#recommendations)
5. [Remediation Priority](#remediation-priority)

---

## 1. Dependency Vulnerabilities

### Critical Findings

The `yarn audit` scan revealed **10 distinct security advisories** affecting multiple transitive dependencies:

#### 1.1 High Severity Vulnerabilities

##### **CVE-2022-3517** - minimatch ReDoS vulnerability
- **Severity:** HIGH (CVSS 7.5)
- **Affected Package:** minimatch < 3.0.5 (currently using 3.0.4)
- **Impact:** Regular Expression Denial of Service (ReDoS) when calling braceExpand function
- **Attack Vector:** Network (AV:N)
- **Paths:** 9+ dependency paths through eslint and related packages
- **Remediation:** Upgrade to minimatch 3.0.5 or later
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-1333 (Inefficient Regular Expression)

##### **CVE-2022-46175** - Prototype Pollution in JSON5
- **Severity:** HIGH (CVSS 7.1)
- **Affected Package:** json5 < 1.0.2 (currently using 1.0.1)
- **Impact:** Prototype pollution via `__proto__` key parsing, allowing arbitrary property injection
- **Attack Vector:** Allows attackers to bypass security checks by polluting object prototypes
- **Paths:** Via eslint-plugin-import > tsconfig-paths > json5
- **Remediation:** Upgrade to json5 1.0.2 or later
- **CWE:** CWE-1321 (Prototype Pollution)

##### **CVE-2024-4068** - Uncontrolled Resource Consumption in braces
- **Severity:** HIGH (CVSS 7.5)
- **Affected Package:** braces < 3.0.3 (currently using 3.0.2)
- **Impact:** Memory exhaustion via imbalanced braces causing infinite parsing loop
- **Attack Vector:** Network (AV:N)
- **Paths:** Via chokidar and micromatch dependencies
- **Remediation:** Upgrade to braces 3.0.3 or later
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-1050

#### 1.2 Moderate Severity Vulnerabilities

##### **CVE-2021-23343** - ReDoS in path-parse
- **Severity:** MODERATE (CVSS 5.3)
- **Affected Package:** path-parse < 1.0.7 (currently using 1.0.6)
- **Impact:** Regular Expression Denial of Service via splitDeviceRe, splitTailRe, and splitPathRe
- **Paths:** 8+ paths through standard-version and eslint-plugin-import
- **Remediation:** Upgrade to path-parse 1.0.7 or later
- **CWE:** CWE-400

##### **CVE-2021-23362** - ReDoS in hosted-git-info
- **Severity:** MODERATE (CVSS 5.3)
- **Affected Package:** hosted-git-info < 2.8.9 (currently using 2.8.8)
- **Impact:** ReDoS via shortcutMatch regex in fromUrl function
- **Paths:** Via standard-version dependency chain
- **Remediation:** Upgrade to hosted-git-info 2.8.9 or later
- **CWE:** CWE-400

##### **CVE-2022-25875** - XSS in Svelte during SSR
- **Severity:** MODERATE (CVSS 6.1)
- **Affected Package:** svelte < 3.49.0 (currently using 3.47.0)
- **Impact:** Cross-site Scripting when using objects with custom toString() during Server-Side Rendering
- **Note:** This is particularly relevant as the plugin uses Svelte components
- **Remediation:** Upgrade to svelte 3.49.0 or later
- **CWE:** CWE-79 (Cross-site Scripting)

##### **CVE-2024-45047** - Potential mXSS in Svelte
- **Severity:** MODERATE (CVSS 5.4)
- **Affected Package:** svelte < 4.2.19 (currently using 3.47.0)
- **Impact:** XSS vulnerability due to improper HTML escaping in `<noscript>` tags
- **Remediation:** Upgrade to svelte 4.2.19 or later
- **CWE:** CWE-79

##### **CVE-2024-28863** - DoS in tar package
- **Severity:** MODERATE (CVSS 6.5)
- **Affected Package:** tar < 6.2.1 (currently using 6.1.11)
- **Impact:** Denial of service via malformed tar archives with excessive folder depth
- **Paths:** Via sass > chokidar > fsevents > node-gyp > tar
- **Remediation:** Upgrade to tar 6.2.1 or later
- **CWE:** CWE-400

##### **CVE-2024-4067** - ReDoS in micromatch
- **Severity:** MODERATE (CVSS 5.3)
- **Affected Package:** micromatch < 4.0.8 (currently using 4.0.4)
- **Impact:** Regular Expression Denial of Service in braces() function
- **Paths:** Via fast-glob and globby dependencies
- **Remediation:** Upgrade to micromatch 4.0.8 or later
- **CWE:** CWE-1333

#### 1.3 Low Severity Vulnerabilities

##### **CVE-2023-42282** - IP Address Validation Bypass
- **Severity:** LOW (CVSS 0)
- **Affected Package:** ip < 1.1.9 (currently using 1.1.5)
- **Impact:** isPublic() incorrectly identifies certain private IPs as public, potential SSRF risk
- **Paths:** Via sass > chokidar > fsevents > node-gyp > socks-proxy-agent
- **Remediation:** Upgrade to ip 1.1.9 or later
- **CWE:** CWE-918 (Server-Side Request Forgery)

### 1.4 Dependency Summary

| Severity | Count | Packages Affected |
|----------|-------|-------------------|
| High | 3 | minimatch, json5, braces |
| Moderate | 6 | path-parse, hosted-git-info, svelte (2 CVEs), tar, micromatch |
| Low | 1 | ip |
| **Total** | **10** | **9 unique packages** |

---

## 2. Code Security Analysis

### 2.1 Positive Findings

The code audit revealed several **good security practices**:

1. **No Hardcoded Secrets:** No API keys, passwords, tokens, or credentials found in source code
2. **No Dangerous Code Execution:** No use of `eval()`, `Function()` constructor, or similar dangerous functions
3. **No Direct HTML Injection:** No use of `innerHTML`, `outerHTML`, or `dangerouslySetInnerHTML`
4. **No Prototype Pollution:** No direct manipulation of `__proto__`, `constructor`, or `prototype` properties
5. **Input Validation:** File path and format validation implemented in `src/settings/validation.ts`
6. **Safe File Operations:** Uses Obsidian's vault API instead of direct filesystem access
7. **Path Normalization:** Properly uses `normalizePath()` before file operations

### 2.2 Security Concerns

#### 2.2.1 Template String Processing (Medium Risk)

**Location:** `src/utils.ts:40-164` - `applyTemplateTransformations()`

**Issue:** The function performs template substitutions using regex `.replace()` on user-provided template content. While the current implementation uses controlled replacements, there are potential risks:

```typescript
templateContents = rawTemplateContents
  .replace(/{{\s*date\s*}}/gi, filename)
  .replace(/{{\s*time\s*}}/gi, window.moment().format("HH:mm"))
  .replace(/{{\s*title\s*}}/gi, filename);
```

**Concern:**
- If `filename` or other replaced values contain special characters or malicious content, they could be injected into the template
- The `filename` is derived from user-controlled format strings via `date.format(format)`
- Moment.js format strings could potentially produce unexpected output

**Recommendation:**
- Sanitize or escape special characters in replaced values
- Validate filename format more strictly
- Consider using a safer templating engine with auto-escaping

#### 2.2.2 Path Handling (Low Risk)

**Location:** `src/utils.ts:260-280` - `join()` function

**Issue:** Custom path joining implementation

```typescript
export function join(...partSegments: string[]): string {
  let parts: string[] = [];
  for (let i = 0, l = partSegments.length; i < l; i++) {
    parts = parts.concat(partSegments[i].split("/"));
  }
  // ... removes "." but does NOT handle ".."
```

**Concern:**
- The function filters out `.` but does not explicitly handle `..` for parent directory traversal
- While Obsidian's `normalizePath()` is used afterward, relying solely on it could be risky

**Current Mitigation:**
- All paths are normalized using `normalizePath()` in `getNoteCreationPath()`
- Uses Obsidian's vault API which provides sandboxing

**Recommendation:**
- Add explicit `..` handling in the join function
- Document the security assumption that Obsidian's vault provides sandboxing

#### 2.2.3 Regex Parsing Patterns (Low Risk)

**Location:** `src/parser.ts:11-14`

**Issue:** Regex patterns used for date parsing:

```typescript
const FULL_DATE_PREFIX = /(\d{4})[-.]?(0[1-9]|1[0-2])[-.]?(0[1-9]|[12][0-9]|3[01])/;
const MONTH_PREFIX = /(\d{4})[-.]?(0[1-9]|1[0-2])/;
const YEAR_PREFIX = /(\d{4})/;
```

**Concern:**
- These patterns are relatively simple and unlikely to cause ReDoS
- However, they could match unintended strings

**Current Mitigation:**
- Patterns are simple with no nested quantifiers or backtracking
- Used only for parsing filenames, not untrusted external input

**Risk Assessment:** Minimal

#### 2.2.4 UI Input Handling (Low Risk)

**Location:** `src/ui/file-suggest.ts` and Svelte components

**Issue:** User input from text fields is used to filter and display files

**Concern:**
- User input from file/folder suggestion fields is used in path comparisons
- Svelte component in `NoteFormatSetting.svelte` displays formatted moment output directly

**Current Mitigation:**
- Uses Obsidian's built-in `setText()` method for rendering, which should escape content
- Svelte's default behavior escapes HTML in templates
- No direct HTML rendering

**Risk Assessment:** Minimal (relies on framework safety)

### 2.3 Configuration Security

#### .gitignore Analysis

The `.gitignore` file properly excludes:
- `node_modules/`
- `.env` files
- Build artifacts (`dist/`, `main.js`)
- Sensitive data files (`data.json`)

**Finding:** SECURE - Proper exclusion of sensitive files

---

## 3. Recommendations

### 3.1 Immediate Actions (Priority: CRITICAL)

1. **Update All Dependencies**
   ```bash
   yarn upgrade svelte@^4.2.19
   yarn upgrade-interactive --latest
   ```

2. **Address High-Severity CVEs**
   - Update minimatch to >=3.0.5
   - Update json5 to >=1.0.2
   - Update braces to >=3.0.3

3. **Svelte Security Patches**
   - Upgrade Svelte from 3.47.0 to 4.2.19+ to patch two XSS vulnerabilities
   - Note: This is a major version upgrade and will require code changes

### 3.2 Short-term Actions (Priority: HIGH)

4. **Update Moderate-Severity Packages**
   - path-parse to >=1.0.7
   - hosted-git-info to >=2.8.9
   - tar to >=6.2.1
   - micromatch to >=4.0.8

5. **Code Security Enhancements**
   - Add input sanitization to `applyTemplateTransformations()`
   - Strengthen path validation in `join()` function
   - Add unit tests for security-critical functions

### 3.3 Long-term Actions (Priority: MEDIUM)

6. **Dependency Management**
   - Implement automated dependency scanning (GitHub Dependabot, Snyk)
   - Establish regular update schedule (monthly security patches)
   - Pin dependency versions with exact ranges for production

7. **Security Testing**
   - Add fuzzing tests for template processing
   - Implement CSP (Content Security Policy) headers if applicable
   - Add integration tests for path traversal prevention

8. **Documentation**
   - Document security assumptions (e.g., Obsidian vault sandboxing)
   - Create security policy (SECURITY.md)
   - Add security testing to CI/CD pipeline

---

## 4. Remediation Priority

### Phase 1: Critical (Within 1 week)
- [ ] Upgrade minimatch (CVE-2022-3517)
- [ ] Upgrade json5 (CVE-2022-46175)
- [ ] Upgrade braces (CVE-2024-4068)
- [ ] Run full test suite after updates

### Phase 2: High (Within 2 weeks)
- [ ] Plan Svelte 3 → 4 migration
- [ ] Update all moderate-severity packages
- [ ] Add automated dependency scanning
- [ ] Create security test cases

### Phase 3: Medium (Within 1 month)
- [ ] Complete Svelte 4 migration
- [ ] Implement enhanced input validation
- [ ] Add security documentation
- [ ] Establish update schedule

---

## 5. Testing Recommendations

After applying fixes, perform the following tests:

1. **Dependency Security Scan**
   ```bash
   yarn audit
   npm audit
   ```

2. **Functionality Testing**
   - Test all note creation workflows (daily, weekly, monthly, quarterly, yearly)
   - Verify template substitutions work correctly
   - Test file/folder suggestion features
   - Validate path handling with edge cases

3. **Security Testing**
   - Test with filenames containing special characters: `<>:"/\|?*`
   - Test with format strings containing escape sequences
   - Test path traversal attempts: `../../sensitive-file`
   - Test template injection attempts

---

## 6. Conclusion

This security audit has identified significant vulnerabilities in the Obsidian Periodic Notes plugin, primarily stemming from **outdated dependencies**. The code itself follows reasonably good security practices, but several areas could be strengthened.

**Key Takeaways:**
- **10 dependency vulnerabilities** need to be addressed
- **3 high-severity** and **6 moderate-severity** CVEs require immediate attention
- Code security is generally good but could benefit from enhanced validation
- The plugin hasn't been updated in years, making it vulnerable to known exploits

**Recommended Action:** Prioritize dependency updates, particularly for high-severity CVEs, and establish a regular maintenance schedule to prevent future security debt.

---

## Appendix A: Vulnerable Dependency Tree

```
obsidian-periodic-notes@0.0.17
├── svelte@3.47.0 (CVE-2022-25875, CVE-2024-45047)
├── eslint@8.13.0
│   └── minimatch@3.0.4 (CVE-2022-3517)
├── eslint-plugin-import
│   └── json5@1.0.1 (CVE-2022-46175)
├── sass
│   └── chokidar
│       ├── braces@3.0.2 (CVE-2024-4068)
│       └── fsevents
│           └── node-gyp
│               ├── tar@6.1.11 (CVE-2024-28863)
│               └── socks-proxy-agent
│                   └── ip@1.1.5 (CVE-2023-42282)
├── svelte-check
│   └── fast-glob
│       └── micromatch@4.0.4 (CVE-2024-4067)
└── standard-version
    ├── path-parse@1.0.6 (CVE-2021-23343)
    └── hosted-git-info@2.8.8 (CVE-2021-23362)
```

---

## Appendix B: Tools Used

- `yarn audit` - Dependency vulnerability scanning
- Manual code review - Static analysis of TypeScript/JavaScript source
- Pattern matching (grep) - Search for security anti-patterns
- File system analysis - Configuration and secret scanning

---

**Report End**
