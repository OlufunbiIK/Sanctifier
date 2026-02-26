# Contract Analysis — Playwright E2E Test Suite

End-to-end tests for the **contract upload → analysis report** flow using [Playwright](https://playwright.dev/).

---

## Files

| File                        | Purpose                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| `contract-analysis.spec.ts` | Full test suite (40+ tests across 7 groups)                        |
| `fixtures.ts`               | Page Object Model, mock helpers, and custom test fixtures          |
| `playwright.config.ts`      | Playwright configuration (browsers, retries, reporter, dev server) |

---

## Quick Start

```bash
# Install dependencies
npm install -D @playwright/test

# Install browser binaries
npx playwright install

# Start your dev server (in a separate terminal)
npm run dev

# Run all tests
npx playwright test contract-analysis.spec.ts

# Run a specific group
npx playwright test --grep "Happy path"

# Run on a single browser
npx playwright test --project=chromium

# Open the HTML report after a run
npx playwright show-report
```

---

## Environment Variables

| Variable   | Default                 | Description                                                        |
| ---------- | ----------------------- | ------------------------------------------------------------------ |
| `BASE_URL` | `http://localhost:3000` | URL of the running app                                             |
| `CI`       | unset                   | Set to any value in CI to enable retries and strict failure limits |

---

## Test Groups

### Happy Path

Core upload-to-report flow: file selection, upload progress, polling, report rendering (risk score, findings, verification results, metadata).

### File Validation

Client-side guards: wrong file type (non-.sol), oversized file, empty file, disabled submit button.

### Drag and Drop

Drop zone highlight on `dragover`, removed on `dragleave`.

### Error States

Server 500, retry flow, analysis timeout, malformed JSON response, HTTP 413.

### Report Actions

PDF/JSON download, severity filter, "Analyze another" reset, copy finding link.

### Accessibility

Keyboard navigation, `aria-live` error announcements, ARIA roles on the findings list, descriptive `aria-label` on the risk badge.

### Visual Regression

Screenshot comparisons for the upload page and a completed report (update with `--update-snapshots`).

---

## Using the Page Object Model

Import from `fixtures.ts` to use the `AnalyzePage` POM in your own tests:

```typescript
import { test, expect } from "./fixtures";

test("risk score is correct", async ({ analyzePage, contractPath }) => {
  await analyzePage.mockUploadSuccess();
  await analyzePage.mockAnalysisComplete();
  await analyzePage.goto();
  await analyzePage.uploadAndSubmit(contractPath);
  await analyzePage.waitForReport();
  await analyzePage.expectRiskScore(72, "medium");
});
```

---

## Required `data-testid` Attributes

The tests expect the following `data-testid` attributes in the application:

**Upload page**

- `upload-zone` — the drag-and-drop area
- `submit-upload-btn` — the submit button
- `selected-filename` — displays the chosen file name
- `upload-progress` — progress indicator during upload
- `file-type-error`, `file-size-error`, `file-empty-error` — inline validation errors
- `upload-error-message` — server-side upload error
- `retry-btn` — retry button on error

**Analysis in progress**

- `analysis-spinner` — spinner while polling
- `analysis-timeout-error` — timeout error state
- `parse-error-message` — malformed response error

**Report**

- `report-container` — root report element
- `risk-score-badge` — risk score + level
- `issue-count-{severity}` — e.g., `issue-count-high`
- `findings-list` — `role="list"` container
- `finding-card` — individual finding (multiple)
- `finding-severity`, `finding-title`, `finding-description`, `finding-recommendation`, `finding-location` — within each card
- `verification-results` — formal verification section
- `report-metadata` — LOC and engine version
- `download-report-btn` — download action
- `severity-filter-{severity}` — e.g., `severity-filter-high`
- `analyze-another-btn` — reset to upload form
- `copy-finding-link-btn` — within each expanded finding

---

## CI Integration

The config automatically detects `process.env.CI` and enables:

- 1 retry on flaky tests
- Stop after 3 consecutive failures
- GitHub Actions reporter (`[[\"github\"]]`)
- HTML report saved to `playwright-report/`

Add to your GitHub Actions workflow:

```yaml
- name: Install Playwright browsers
  run: npx playwright install --with-deps

- name: Run E2E tests
  run: npx playwright test
  env:
    CI: true
    BASE_URL: http://localhost:3000

- name: Upload Playwright report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: playwright-report
    path: playwright-report/
```
