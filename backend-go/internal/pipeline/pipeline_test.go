package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"moderation/internal/domain"
	"moderation/internal/osv"
	"moderation/internal/pipeline"
	"moderation/internal/policy"
	"moderation/internal/registry"
	"moderation/internal/reports"
	"moderation/internal/sandbox"
	"moderation/internal/scanners"
	"moderation/internal/storage"
)

// --------------------------------------------------------------------- —à–∞–≥–∏ 0‚Äì3

func TestDbCheckTerminalBranches(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	cases := []struct{ initial, wantStatus, wantResult string }{
		{"approved", "approved", "pass"},
		{"blacklisted", "blacklisted", "fail"},
		{"revoked", "revoked", "fail"},
	}
	for _, c := range cases {
		t.Run(c.initial, func(t *testing.T) {
			e := newEnv(t, r)
			pkg, ver, item := setup(t, r, "requests", "2.31.0-"+c.initial)
			if err := r.UpdatePackageVersionStatus(ctx, ver.ID, c.initial, nil); err != nil {
				t.Fatalf("–ø–æ–¥–≥–æ—Ç–æ–≤–∫–∞ –≤–µ—Ä—Å–∏–∏: %v", err)
			}
			ver.Status = c.initial

			res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.ItemStatus != c.wantStatus {
				t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è %q", res.ItemStatus, c.wantStatus)
			}
			steps := stepsByCode(t, r, item.ID)
			if len(steps) != 1 || steps["db_check"].Result != c.wantResult {
				t.Fatalf("–æ–∂–∏–¥–∞–ª—Å—è –µ–¥–∏–Ω—Å—Ç–≤–µ–Ω–Ω—ã–π db_check/%s, –ø–æ–ª—É—á–µ–Ω–æ %+v", c.wantResult, steps)
			}
		})
	}
}

func TestBlacklistStopsBeforeDownload(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "left-pad", "1.3.0")
	pc := e.context(pkg, ver, item)
	// –ü—Ä–∞–≤–∏–ª–æ –ø–æ glob: –∏–º—è –ø–∞–∫–µ—Ç–∞ namespace'–∏—Ç—Å—è –∏–º–µ–Ω–µ–º —Ç–µ—Å—Ç–∞ (—Å–º. setup).
	pc.BL = &policy.Blacklist{Rules: []policy.Rule{
		{Name: "left-pad*", Versions: "*", Reason: "–∏—Å—Ç–æ—Ä–∏—á–µ—Å–∫–∏ –ø—Ä–æ–±–ª–µ–º–Ω—ã–π –ø–∞–∫–µ—Ç"},
	}}

	res, err := pipeline.Run(ctx, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "blacklisted" {
		t.Fatalf("ItemStatus = %q", res.ItemStatus)
	}
	// –ó–∞–ø—Ä–µ—â—ë–Ω–Ω—ã–π –ø–∞–∫–µ—Ç –Ω–∞—Ä—É–∂—É –Ω–µ —Å–∫–∞—á–∏–≤–∞–µ—Ç—Å—è ‚Äî —ç—Ç–æ –≤–µ—Å—å —Å–º—ã—Å–ª —à–∞–≥–∞.
	if e.fetcher.calls != 0 {
		t.Errorf("–≤—ã–ø–æ–ª–Ω–µ–Ω–æ —Å–∫–∞—á–∏–≤–∞–Ω–∏–π: %d ‚Äî –∑–∞–ø—Ä–µ—â—ë–Ω–Ω—ã–π –ø–∞–∫–µ—Ç —É—à—ë–ª –Ω–∞—Ä—É–∂—É", e.fetcher.calls)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["blacklist"].Result != "fail" || len(steps) != 2 {
		t.Errorf("—à–∞–≥–∏ = %+v", steps)
	}
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "blacklisted" {
		t.Errorf("—Å—Ç–∞—Ç—É—Å –≤–µ—Ä—Å–∏–∏ = %q", got.Status)
	}
}

func TestQuarantineHoldsFreshVersion(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "fresh-pkg", "1.0.0")
	published := e.now.AddDate(0, 0, -2)
	ver.PublishedAt = &published

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "quarantined" {
		t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è quarantined", res.ItemStatus)
	}
	if e.fetcher.calls != 0 {
		t.Error("–ø–∞–∫–µ—Ç –≤ –∫–∞—Ä–∞–Ω—Ç–∏–Ω–µ —Å–∫–∞—á–∞–Ω")
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["quarantine"].Result != "warn" {
		t.Errorf("quarantine = %q", steps["quarantine"].Result)
	}
	// –ö–∞—Ä–∞–Ω—Ç–∏–Ω ‚Äî –Ω–µ–ø–æ–≥–∞—à–µ–Ω–Ω–∞—è –±–ª–æ–∫–∏—Ä–æ–≤–∫–∞.
	if !pipeline.IsOpenResult("quarantine", steps["quarantine"].Result) {
		t.Error("–∫–∞—Ä–∞–Ω—Ç–∏–Ω –Ω–µ —Å—á–∏—Ç–∞–µ—Ç—Å—è –Ω–µ–ø–æ–≥–∞—à–µ–Ω–Ω–æ–π –±–ª–æ–∫–∏—Ä–æ–≤–∫–æ–π")
	}
}

// TestQuarantineMetadataFailureCanBeReleasedManually ‚Äî –µ—Å–ª–∏ —Ä–µ–µ—Å—Ç—Ä –Ω–µ –¥–∞–ª
// –¥–∞—Ç—É –ø—É–±–ª–∏–∫–∞—Ü–∏–∏, –∏–Ω—Ç–µ—Ä—Ñ–µ–π—Å –ø—Ä–µ–¥–ª–∞–≥–∞–µ—Ç DevSecOps —Å–Ω—è—Ç—å –∫–∞—Ä–∞–Ω—Ç–∏–Ω –≤—Ä—É—á–Ω—É—é.
// –î–ª—è —ç—Ç–æ–≥–æ —Å—Ç–∞—Ç—É—Å –æ–±—è–∑–∞–Ω –±—ã—Ç—å quarantined: ReleaseQuarantine –Ω–µ –ø—Ä–∏–Ω–∏–º–∞–µ—Ç
// awaiting_security, –∏ –ø—Ä–µ–∂–Ω–µ–µ –∑–Ω–∞—á–µ–Ω–∏–µ –¥–µ–ª–∞–ª–æ –∫–Ω–æ–ø–∫—É –≥–∞—Ä–∞–Ω—Ç–∏—Ä–æ–≤–∞–Ω–Ω–æ –±–∏—Ç–æ–π.
func TestQuarantineMetadataFailureCanBeReleasedManually(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.registry = registry.New(registry.Config{
		PyPIURL: "https://pypi.test",
		HTTP:    &fakeRegistryHTTP{err: fmt.Errorf("connection refused")},
	})
	pkg, ver, item := setup(t, r, "metadata-unavailable", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "quarantined" {
		t.Fatalf("ItemStatus = %q, –∫–Ω–æ–ø–∫–∞ —Å–Ω—è—Ç–∏—è –∫–∞—Ä–∞–Ω—Ç–∏–Ω–∞ —Ç—Ä–µ–±—É–µ—Ç quarantined", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["quarantine"].Result != "warn" {
		t.Errorf("quarantine = %q, –æ–∂–∏–¥–∞–ª—Å—è warn", steps["quarantine"].Result)
	}
}

func TestQuarantineMissingVersionFailsInsteadOfWaitingForManualRelease(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.registry = registry.New(registry.Config{
		PyPIURL: "https://pypi.test",
		HTTP:    &fakeRegistryHTTP{responses: map[string]string{}},
	})
	pkg, ver, item := setup(t, r, "missing-version", "99.99.99")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "failed" {
		t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è failed", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["quarantine"].Result != "fail" {
		t.Errorf("quarantine = %q, –æ–∂–∏–¥–∞–ª—Å—è fail", steps["quarantine"].Result)
	}
}

// TestLicenseDoesNotStopPipeline ‚Äî —Ü–µ–Ω—Ç—Ä–∞–ª—å–Ω–∞—è –º–µ—Ö–∞–Ω–∏–∫–∞ —Å–µ—Ä–≤–∏—Å–∞: —à–∞–≥ –ª–∏—Ü–µ–Ω–∑–∏–∏,
// –Ω–µ –ø—Ä–æ–π–¥–µ–Ω–Ω—ã–π –∞–≤—Ç–æ–º–∞—Ç–∏—á–µ—Å–∫–∏, –∫–æ–Ω–≤–µ–π–µ—Ä –ù–ï –æ—Å—Ç–∞–Ω–∞–≤–ª–∏–≤–∞–µ—Ç. –ü–∞–∫–µ—Ç —É—Ö–æ–¥–∏—Ç –¥–∞–ª—å—à–µ
// –Ω–∞ —Å–∫–∞—á–∏–≤–∞–Ω–∏–µ –∏ —Å–∫–∞–Ω–∏—Ä–æ–≤–∞–Ω–∏–µ, —á—Ç–æ–±—ã DevSecOps —É–≤–∏–¥–µ–ª –µ–≥–æ –≤ —Å–≤–æ–µ–π –æ—á–µ—Ä–µ–¥–∏
// —Å—Ä–∞–∑—É, –∞ –Ω–µ –ø–æ—Å–ª–µ —Ä–µ—à–µ–Ω–∏—è —é—Ä–∏—Å—Ç–∞.
func TestLicenseDoesNotStopPipeline(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)
	// –°–ø—Ä–∞–≤–æ—á–Ω–∏–∫ –Ω–µ —Ä–∞–∑—Ä–µ—à–∞–µ—Ç –Ω–∏—á–µ–≥–æ ‚Äî –ª–∏—Ü–µ–Ω–∑–∏—è —É—Ö–æ–¥–∏—Ç —é—Ä–∏—Å—Ç—É.
	pc.Lic = licensePolicy()

	res, err := pipeline.Run(ctx, pc, "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	steps := stepsByCode(t, r, item.ID)
	if steps["license"].Result != "warn" {
		t.Fatalf("license = %q, –æ–∂–∏–¥–∞–ª—Å—è warn", steps["license"].Result)
	}
	// –ö–æ–Ω–≤–µ–π–µ—Ä –ø–æ—à—ë–ª –¥–∞–ª—å—à–µ: —Å–∫–∞—á–∏–≤–∞–Ω–∏–µ –∏ —Å–∫–∞–Ω–∏—Ä–æ–≤–∞–Ω–∏–µ –≤—ã–ø–æ–ª–Ω–µ–Ω—ã.
	for _, code := range []string{"download", "vuln_scan", "sandbox_scan"} {
		if _, ok := steps[code]; !ok {
			t.Errorf("—à–∞–≥ %s –Ω–µ –≤—ã–ø–æ–ª–Ω–µ–Ω ‚Äî –∫–æ–Ω–≤–µ–π–µ—Ä –æ—Å—Ç–∞–Ω–æ–≤–∏–ª—Å—è –Ω–∞ –ª–∏—Ü–µ–Ω–∑–∏–∏", code)
		}
	}
	if e.fetcher.calls != 1 {
		t.Errorf("—Å–∫–∞—á–∏–≤–∞–Ω–∏–π: %d, –æ–∂–∏–¥–∞–ª–æ—Å—å 1", e.fetcher.calls)
	}
	// –ü—É–±–ª–∏–∫–∞—Ü–∏—è –ø—Ä–∏ —ç—Ç–æ–º –ù–ï —Å–æ—Å—Ç–æ—è–ª–∞—Å—å.
	if steps["publish"].Result != "warn" {
		t.Errorf("publish = %q, –æ–∂–∏–¥–∞–ª—Å—è warn (–ø—É–±–ª–∏–∫–∞—Ü–∏—è –æ—Ç–ª–æ–∂–µ–Ω–∞)", steps["publish"].Result)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –Ω–µ–ø–æ–≥–∞—à–µ–Ω–Ω–æ–π –±–ª–æ–∫–∏—Ä–æ–≤–∫–µ –ª–∏—Ü–µ–Ω–∑–∏–∏")
	}
	if res.ItemStatus != "awaiting_legal" {
		t.Errorf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è awaiting_legal", res.ItemStatus)
	}
}

func TestLicenseIsNotApplicableToExcludedManagers(t *testing.T) {
	// –ö–∞–∂–¥—ã–π –∏—Å–∫–ª—é—á—ë–Ω–Ω—ã–π –º–µ–Ω–µ–¥–∂–µ—Ä –¥–æ–ª–∂–µ–Ω –ø—Ä–æ–π—Ç–∏ —à–∞–≥ –±–µ–∑ —Ä–µ–µ—Å—Ç—Ä–∞ –ª–∏—Ü–µ–Ω–∑–∏–π,
	// –º–µ—Ç–∞–¥–∞–Ω–Ω—ã—Ö –∏ –æ–±—Ä–∞—â–µ–Ω–∏—è –∫ –≤–Ω–µ—à–Ω–∏–º –∑–∞–≤–∏—Å–∏–º–æ—Å—Ç—è–º.
	for _, manager := range []string{"docker", "files", "git", "luarocks", "terraform"} {
		t.Run(manager, func(t *testing.T) {
			outcome, err := (pipeline.LicenseStep{}).Run(context.Background(), &pipeline.Context{
				Package: &domain.Package{Manager: manager},
			})
			if err != nil {
				t.Fatalf("LicenseStep.Run: %v", err)
			}
			if outcome.Result != "skipped" || outcome.Stop || outcome.Defer {
				t.Fatalf("—Ä–µ–∑—É–ª—å—Ç–∞—Ç = %+v, –æ–∂–∏–¥–∞–ª—Å—è –Ω–µ–±–ª–æ–∫–∏—Ä—É—é—â–∏–π skipped", outcome)
			}
			if applicable, ok := outcome.Details["applicable"].(bool); !ok || applicable {
				t.Fatalf("details.applicable = %#v, –æ–∂–∏–¥–∞–ª—Å—è false", outcome.Details["applicable"])
			}
			if outcome.Details["manager"] != manager {
				t.Fatalf("details.manager = %#v, –æ–∂–∏–¥–∞–ª—Å—è %q", outcome.Details["manager"], manager)
			}
		})
	}
}

// --------------------------------------------------------------------- –∑–æ–ª–æ—Ç–æ–π –ø—É—Ç—å

func TestGoldenPathPublishes(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("—Ä–µ–∑—É–ª—å—Ç–∞—Ç = %+v, –æ–∂–∏–¥–∞–ª—Å—è approved/terminal", res)
	}

	steps := stepsByCode(t, r, item.ID)
	if len(steps) != len(domain.StepCodes) {
		t.Fatalf("–≤—ã–ø–æ–ª–Ω–µ–Ω–æ —à–∞–≥–æ–≤: %d, –æ–∂–∏–¥–∞–ª–æ—Å—å %d: %+v",
			len(steps), len(domain.StepCodes), steps)
	}
	for code, step := range steps {
		if step.Result != "pass" {
			t.Errorf("—à–∞–≥ %s = %q, –æ–∂–∏–¥–∞–ª—Å—è pass", code, step.Result)
		}
	}
	if len(e.artifacts.published) != 1 {
		t.Errorf("–æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω–æ –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–æ–≤: %d", len(e.artifacts.published))
	}
	// –û—Å–Ω–æ–≤–Ω–æ–π –ø—É—Ç—å –ø—É–±–ª–∏–∫–∞—Ü–∏–∏ ‚Äî –ø–µ—Ä–µ–Ω–æ—Å —Ñ–∞–π–ª–∞ –≤–Ω—É—Ç—Ä–∏ –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–æ—Ä–∏, –±–µ–∑
	// –ø—Ä–æ–≥–æ–Ω–∞ –±–∞–π—Ç–æ–≤ —á–µ—Ä–µ–∑ —Å–µ—Ä–≤–∏—Å. –ó–∞–ø–∞—Å–Ω–æ–π (—Å–∫–∞—á–∞—Ç—å –∏ –≤—ã–≥—Ä—É–∑–∏—Ç—å) —Å—É—â–µ—Å—Ç–≤—É–µ—Ç
	// –¥–ª—è Nexus, –∏ –ø—Ä–æ–≤–µ—Ä—è—Ç—å –ø–æ –Ω–µ–º—É –∑–æ–ª–æ—Ç–æ–π –ø—É—Ç—å –∑–Ω–∞—á–∏–ª–æ –±—ã –Ω–µ –∑–∞–º–µ—Ç–∏—Ç—å, —á—Ç–æ
	// –ø–µ—Ä–µ–Ω–æ—Å —Å–ª–æ–º–∞–ª—Å—è.
	if mode := steps["publish"].Details["publish_mode"]; mode != "move" {
		t.Errorf("—Å–ø–æ—Å–æ–± –ø—É–±–ª–∏–∫–∞—Ü–∏–∏ = %v, –æ–∂–∏–¥–∞–ª—Å—è –ø–µ—Ä–µ–Ω–æ—Å –≤–Ω—É—Ç—Ä–∏ –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–æ—Ä–∏", mode)
	}
	// –ü—Ä–æ–º–µ–∂—É—Ç–æ—á–Ω–∞—è –∑–æ–Ω–∞ –≤—Ä–µ–º–µ–Ω–Ω–∞—è: —Ñ–∞–π–ª —É—Ö–æ–¥–∏—Ç –∏–∑ –Ω–µ—ë —Å—Ä–∞–∑—É –ø–æ—Å–ª–µ –ø—É–±–ª–∏–∫–∞—Ü–∏–∏.
	objects, err := e.storage.List(ctx, "pypi/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Errorf("—Ñ–∞–π–ª –æ—Å—Ç–∞–ª—Å—è –≤ –ø—Ä–æ–º–µ–∂—É—Ç–æ—á–Ω–æ–π –∑–æ–Ω–µ –ø–æ—Å–ª–µ –ø—É–±–ª–∏–∫–∞—Ü–∏–∏: %+v", objects)
	}
	// –ê –æ—Ç—á—ë—Ç—ã ‚Äî –æ—Å—Ç–∞—é—Ç—Å—è, –∏ –≤ —Å–≤–æ—ë–º —Ö—Ä–∞–Ω–∏–ª–∏—â–µ.
	if got, _ := e.reports.List(ctx, "reports/"); len(got) != 2 {
		t.Errorf("—Ñ–∞–π–ª–æ–≤ –æ—Ç—á—ë—Ç–æ–≤: %d, –æ–∂–∏–¥–∞–ª–æ—Å—å 2 (–æ–¥–∏–Ω —à–∞–≥ —Å–∫–∞–Ω–∏—Ä–æ–≤–∞–Ω–∏—è √ó json+html)", len(got))
	}

	artifact, err := r.CurrentArtifact(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Status != "published" || artifact.NexusURL == nil {
		t.Errorf("–∞—Ä—Ç–µ—Ñ–∞–∫—Ç = %+v", artifact)
	}
	if artifact.StagingClearedAt == nil {
		t.Error("–≤—Ä–µ–º—è –æ—á–∏—Å—Ç–∫–∏ –ø—Ä–æ–º–µ–∂—É—Ç–æ—á–Ω–æ–π –∑–æ–Ω—ã –Ω–µ –ø—Ä–æ—Å—Ç–∞–≤–ª–µ–Ω–æ")
	}
}

// --------------------------------------------------------------------- —à–∞–≥ 4

func TestDownloadRejectsChecksumMismatch(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// –†–µ–µ—Å—Ç—Ä –∑–∞—è–≤–ª—è–µ—Ç sha256, –∫–æ—Ç–æ—Ä—ã–π –Ω–µ —Å–æ–≤–ø–∞–¥—ë—Ç —Å —Å–æ–¥–µ—Ä–∂–∏–º—ã–º.
	e.registry = registryWithChecksum(t, "sha256",
		"0000000000000000000000000000000000000000000000000000000000000000")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "failed" {
		t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è failed", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["download"].Result != "fail" {
		t.Fatalf("download = %q", steps["download"].Result)
	}
	if !strings.Contains(*steps["download"].Message, "–ö–æ–Ω—Ç—Ä–æ–ª—å–Ω–∞—è —Å—É–º–º–∞") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q", *steps["download"].Message)
	}
	// –ê—Ä—Ç–µ—Ñ–∞–∫—Ç —Å –Ω–µ—Å–æ–≤–ø–∞–≤—à–µ–π —Å—É–º–º–æ–π –Ω–µ –¥–æ–ª–∂–µ–Ω –ø–æ–ø–∞—Å—Ç—å –≤ —Ö—Ä–∞–Ω–∏–ª–∏—â–µ.
	if objects, _ := e.storage.List(ctx, "pypi/"); len(objects) != 0 {
		t.Errorf("–∞—Ä—Ç–µ—Ñ–∞–∫—Ç —Å –Ω–µ–≤–µ—Ä–Ω–æ–π —Å—É–º–º–æ–π –∑–∞–ø–∏—Å–∞–Ω –≤ —Ö—Ä–∞–Ω–∏–ª–∏—â–µ: %+v", objects)
	}
}

// TestDownloadUnknownChecksumAlgoIsNotSilentPass ‚Äî –∞–ª–≥–æ—Ä–∏—Ç–º, –∫–æ—Ç–æ—Ä—ã–π –º—ã –Ω–µ
// —É–º–µ–µ–º —Å—á–∏—Ç–∞—Ç—å (go h1), –Ω–µ –¥–æ–ª–∂–µ–Ω –º–æ–ª—á–∞ —á–∏—Ç–∞—Ç—å—Å—è –∫–∞–∫ ¬´—Å—É–º–º–∞ —Å–æ–≤–ø–∞–ª–∞¬ª.
func TestDownloadUnknownChecksumAlgoIsNotSilentPass(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.registry = registryWithChecksum(t, "h1", "h1:abcdef==")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["download"].Result != "pass" {
		t.Fatalf("download = %q, –Ω–µ–ø–æ–¥–¥–µ—Ä–∂–∞–Ω–Ω—ã–π –∞–ª–≥–æ—Ä–∏—Ç–º –Ω–µ –¥–æ–ª–∂–µ–Ω –≤–∞–ª–∏—Ç—å —à–∞–≥", steps["download"].Result)
	}
	if !strings.Contains(*steps["download"].Message, "–Ω–µ —Å–≤–µ—Ä—è–ª–∞—Å—å") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –Ω–µ —Å–∫–∞–∑–∞–Ω–æ, —á—Ç–æ —Å—É–º–º–∞ –Ω–µ —Å–≤–µ—Ä—è–ª–∞—Å—å", *steps["download"].Message)
	}
}

// --------------------------------------------------------------------- —à–∞–≥ 5

func TestVulnAboveThresholdGoesToSecurity(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	e.index.Records = []osv.Record{criticalRecord(t, pkg.Name)}

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è awaiting_security", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["vuln_scan"].Result != "fail" {
		t.Fatalf("vuln_scan = %q", steps["vuln_scan"].Result)
	}
	// fail —É vuln_scan ‚Äî —ç—Ç–æ –Ω–µ–ø–æ–≥–∞—à–µ–Ω–Ω–∞—è –±–ª–æ–∫–∏—Ä–æ–≤–∫–∞, –∞ –Ω–µ –æ—Ç–∫–∞–∑: —Ä–µ—à–µ–Ω–∏–µ
	// –ø—Ä–∏–Ω–∏–º–∞–µ—Ç DevSecOps.
	if !pipeline.IsOpenResult("vuln_scan", "fail") {
		t.Error("fail —É vuln_scan –Ω–µ —Å—á–∏—Ç–∞–µ—Ç—Å—è –Ω–µ–ø–æ–≥–∞—à–µ–Ω–Ω–æ–π –±–ª–æ–∫–∏—Ä–æ–≤–∫–æ–π")
	}
	// –û—Ç–∫–ª–æ–Ω—ë–Ω–Ω—ã–π –Ω–∞ —à–∞–≥–µ 5 –∞—Ä—Ç–µ—Ñ–∞–∫—Ç –≤—ã—á–∏—â–∞–µ—Ç—Å—è –∏–∑ –∫–∞—Ä–∞–Ω—Ç–∏–Ω–Ω–æ–π –∑–æ–Ω—ã —Å—Ä–∞–∑—É.
	if objects, _ := e.storage.List(ctx, "pypi/"); len(objects) != 0 {
		t.Errorf("–∞—Ä—Ç–µ—Ñ–∞–∫—Ç –Ω–µ –≤—ã—á–∏—â–µ–Ω –ø–æ—Å–ª–µ –æ—Ç–∫–ª–æ–Ω–µ–Ω–∏—è: %+v", objects)
	}
	// –£—è–∑–≤–∏–º–æ—Å—Ç—å —Å–æ—Ö—Ä–∞–Ω–µ–Ω–∞.
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxVulnScore == nil || *got.MaxVulnScore < 90 {
		t.Errorf("MaxVulnScore = %v", got.MaxVulnScore)
	}
}

// TestStaleIndexDoesNotAutoApprove ‚Äî –º–æ–ª—á–∞ –æ–¥–æ–±—Ä—è—Ç—å –Ω–∞ —É—Å—Ç–∞—Ä–µ–≤—à–∏—Ö –¥–∞–Ω–Ω—ã—Ö –Ω–µ–ª—å–∑—è.
func TestStaleIndexDoesNotAutoApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	old := e.now.AddDate(0, 0, -30)
	e.index.Version = &osv.IndexVersion{Version: "stale-1", Source: "static", PublishedAt: &old}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, —É—Å—Ç–∞—Ä–µ–≤—à–∞—è –±–∞–∑–∞ –¥–æ–ª–∂–Ω–∞ –∑–≤–∞—Ç—å DevSecOps", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["vuln_scan"].Result != "warn" {
		t.Fatalf("vuln_scan = %q", steps["vuln_scan"].Result)
	}
	if !strings.Contains(*steps["vuln_scan"].Message, "—É—Å—Ç–∞—Ä–µ–ª–∞") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q", *steps["vuln_scan"].Message)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø–æ —É—Å—Ç–∞—Ä–µ–≤—à–µ–π –±–∞–∑–µ —É—è–∑–≤–∏–º–æ—Å—Ç–µ–π")
	}
}

// TestMissingSnapshotDoesNotAutoApprove ‚Äî –æ—Ç—Å—É—Ç—Å—Ç–≤—É—é—â–∏–π —Å–Ω–∞–ø—à–æ—Ç —Ç–æ–∂–µ –Ω–µ ¬´—á–∏—Å—Ç–æ¬ª.
func TestMissingSnapshotDoesNotAutoApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.index.Version = nil // —Å–Ω–∞–ø—à–æ—Ç –Ω–∏ —Ä–∞–∑—É –Ω–µ –∑–∞–≥—Ä—É–∂–∞–ª—Å—è
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q ‚Äî –ø–∞–∫–µ—Ç –ø—Ä–æ—Å–∫–æ—á–∏–ª –±—ã –±–µ–∑ –±–∞–∑—ã —É—è–∑–≤–∏–º–æ—Å—Ç–µ–π", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –±–µ–∑ –∑–∞–≥—Ä—É–∂–µ–Ω–Ω–æ–π –±–∞–∑—ã —É—è–∑–≤–∏–º–æ—Å—Ç–µ–π")
	}
}

// --------------------------------------------------------------------- —à–∞–≥ 6: –ø–µ—Å–æ—á–Ω–∏—Ü–∞

// TestSandboxUnavailableIsNotClean ‚Äî –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –Ω–µ –æ—Ç–≤–µ—Ç–∏–ª–∞. –≠—Ç–æ ¬´–ø—Ä–æ–≤–µ—Ä–∫–∞ –Ω–µ
// –≤—ã–ø–æ–ª–Ω–µ–Ω–∞¬ª, –∞ –Ω–µ ¬´—á–∏—Å—Ç–æ¬ª: –ø—É–±–ª–∏–∫–∞—Ü–∏—è –æ—Å—Ç–∞–Ω–∞–≤–ª–∏–≤–∞–µ—Ç—Å—è, —Ä–µ—à–µ–Ω–∏–µ –ø—Ä–∏–Ω–∏–º–∞–µ—Ç
// DevSecOps. –¢–æ—Ç –∂–µ –ø—Ä–∏–Ω—Ü–∏–ø, —á—Ç–æ —É —É—Å—Ç–∞—Ä–µ–≤—à–µ–≥–æ —Å–Ω–∞–ø—à–æ—Ç–∞ OSV.
func TestSandboxUnavailableIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.err = errors.New("–∑–∞–ø—Ä–æ—Å –∫ –ø–µ—Å–æ—á–Ω–∏—Ü–µ https://sandbox.test: connection refused")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q ‚Äî –Ω–µ–æ—Ç–≤–µ—Ç–∏–≤—à–∞—è –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –ø—Ä–æ—á–∏—Ç–∞–Ω–∞ –∫–∞–∫ ¬´—á–∏—Å—Ç–æ¬ª", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "warn" {
		t.Fatalf("sandbox_scan = %q, –æ–∂–∏–¥–∞–ª—Å—è warn", steps["sandbox_scan"].Result)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –Ω–µ–æ—Ç—Ä–∞–±–æ—Ç–∞–≤—à–µ–π –ø–µ—Å–æ—á–Ω–∏—Ü–µ")
	}
	// –û—Ç—á—ë—Ç –µ—Å—Ç—å, —Å —è–≤–Ω—ã–º —Å–æ—Å—Ç–æ—è–Ω–∏–µ–º unavailable: ¬´–ø—Ä–æ–≤–µ—Ä–∫–∏ –Ω–µ –±—ã–ª–æ¬ª –æ–±—è–∑–∞–Ω–æ
	// –±—ã—Ç—å –≤–∏–¥–Ω–æ, –∞ –Ω–µ –æ—Ç—Å—É—Ç—Å—Ç–≤–æ–≤–∞—Ç—å —Ñ–∞–π–ª–æ–º.
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "unavailable" {
		t.Fatalf("–æ—Ç—á—ë—Ç = %+v, –æ–∂–∏–¥–∞–ª–æ—Å—å —Å–æ—Å—Ç–æ—è–Ω–∏–µ unavailable", report)
	}
	// –ò –Ω–∏–∫–∞–∫–∏—Ö —Å—á—ë—Ç—á–∏–∫–æ–≤ –Ω–∞—Ö–æ–¥–æ–∫: –Ω–æ–ª—å –ø–æ –Ω–µ–≤—ã–ø–æ–ª–Ω–µ–Ω–Ω–æ–π –ø—Ä–æ–≤–µ—Ä–∫–µ ‚Äî –Ω–µ
	// –∏–∑–º–µ—Ä–µ–Ω–∏–µ, –∞ –µ–≥–æ –æ—Ç—Å—É—Ç—Å—Ç–≤–∏–µ. –í –∫–∞—Ä—Ç–æ—á–∫–µ ¬´–Ω–∞–π–¥–µ–Ω–æ: 0¬ª —á–∏—Ç–∞–ª–æ—Å—å —Ä–æ–≤–Ω–æ
	// –Ω–∞–æ–±–æ—Ä–æ—Ç ‚Äî ¬´–ø—Ä–æ–≤–µ—Ä–∏–ª–∏, —á–∏—Å—Ç–æ¬ª.
	if _, ok := steps["sandbox_scan"].Details["findings_total"]; ok {
		t.Errorf("–¥–µ—Ç–∞–ª–∏ —à–∞–≥–∞ = %v ‚Äî —Å—á—ë—Ç—á–∏–∫ –Ω–∞—Ö–æ–¥–æ–∫ –ø–æ –Ω–µ–≤—ã–ø–æ–ª–Ω–µ–Ω–Ω–æ–π –ø—Ä–æ–≤–µ—Ä–∫–µ",
			steps["sandbox_scan"].Details)
	}
}

// TestSandboxNotConfiguredIsNotClean ‚Äî –∞–¥—Ä–µ—Å –ø–µ—Å–æ—á–Ω–∏—Ü—ã –Ω–µ –∑–∞–¥–∞–Ω. –û—Ç–ª–∏—á–∞–µ—Ç—Å—è –æ—Ç
// –ø—Ä–µ–¥—ã–¥—É—â–µ–≥–æ —Ç–µ–º, —á—Ç–æ –¥–æ —Å–µ—Ç–∏ –¥–µ–ª–æ –Ω–µ –¥–æ—à–ª–æ –≤–æ–≤—Å–µ, –∞ –≤–µ—Å—Ç–∏ —Å–µ–±—è –æ–±—è–∑–∞–Ω–æ —Ç–∞–∫
// –∂–µ: –≤—ã–∫–ª—é—á–∞—Ç—å –ø—Ä–æ–≤–µ—Ä–∫—É –º–æ–ª—á–∞, –ø–æ—Ç–æ–º—É —á—Ç–æ –µ—ë –∑–∞–±—ã–ª–∏ –Ω–∞—Å—Ç—Ä–æ–∏—Ç—å, –Ω–µ–ª—å–∑—è.
func TestSandboxNotConfiguredIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.available = false
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q ‚Äî –Ω–µ–Ω–∞—Å—Ç—Ä–æ–µ–Ω–Ω–∞—è –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –ø—Ä–æ—á–∏—Ç–∞–Ω–∞ –∫–∞–∫ ¬´—á–∏—Å—Ç–æ¬ª", res.ItemStatus)
	}
	if e.sandbox.calls != 0 {
		t.Error("–Ω–µ–Ω–∞—Å—Ç—Ä–æ–µ–Ω–Ω–∞—è –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –≤—Å—ë-—Ç–∞–∫–∏ –æ–ø—Ä–æ—à–µ–Ω–∞")
	}
	steps := stepsByCode(t, r, item.ID)
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SANDBOX_URL") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –Ω–µ –Ω–∞–∑–≤–∞–Ω–∞ –Ω–∞—Å—Ç—Ä–æ–π–∫–∞, –∫–æ—Ç–æ—Ä–æ–π –∑–∞–¥–∞—ë—Ç—Å—è –∞–¥—Ä–µ—Å",
			stepMessage(steps["sandbox_scan"]))
	}
}

// TestSandboxDangerousBlocksPublication ‚Äî –≤–µ—Ä–¥–∏–∫—Ç DANGEROUS. –ü—É–±–ª–∏–∫–∞—Ü–∏—è
// –æ—Å—Ç–∞–Ω–∞–≤–ª–∏–≤–∞–µ—Ç—Å—è, –ø–∞–∫–µ—Ç —É—Ö–æ–¥–∏—Ç DevSecOps, –Ω–∞—Ö–æ–¥–∫–∏ –≤–∏–¥–Ω—ã –≤ –∫–∞—Ä—Ç–æ—á–∫–µ –∏ –≤
// –æ—Ç—á—ë—Ç–µ, —Å—Å—ã–ª–∫–∞ –Ω–∞ –∑–∞–¥–∞—á—É –≤ –ø–µ—Å–æ—á–Ω–∏—Ü–µ ‚Äî –≤ –¥–µ—Ç–∞–ª—è—Ö —à–∞–≥–∞.
func TestSandboxDangerousBlocksPublication(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-42",
		Detections: []sandbox.Detection{
			{Name: "Trojan.Generic", Type: "malware", Severity: "critical",
				Details: "—Å–µ—Ç–µ–≤–æ–µ —Å–æ–µ–¥–∏–Ω–µ–Ω–∏–µ —Å C2"},
			{Name: "Persistence.Cron"},
		},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è awaiting_security", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("–ø–∞–∫–µ—Ç —Å –≤–µ—Ä–¥–∏–∫—Ç–æ–º DANGEROUS –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω")
	}

	steps := stepsByCode(t, r, item.ID)
	step := steps["sandbox_scan"]
	if step.Result != "fail" {
		t.Errorf("sandbox_scan = %q, –æ–∂–∏–¥–∞–ª—Å—è fail", step.Result)
	}
	if step.Details["verdict"] != sandbox.VerdictDangerous {
		t.Errorf("–≤–µ—Ä–¥–∏–∫—Ç –≤ –¥–µ—Ç–∞–ª—è—Ö = %v", step.Details["verdict"])
	}
	// –°—Å—ã–ª–∫–∞ –Ω–∞ –∑–∞–¥–∞—á—É ‚Äî —Ç–æ, –ø–æ —á–µ–º—É DevSecOps –æ—Ç–∫—Ä—ã–≤–∞–µ—Ç –æ—Ç—á—ë—Ç –ø–µ—Å–æ—á–Ω–∏—Ü—ã.
	// –ë–µ–∑ –Ω–µ—ë ¬´–ø–æ—Å–º–æ—Ç—Ä–∏—Ç–µ –≤ –ø–µ—Å–æ—á–Ω–∏—Ü–µ¬ª –æ–∑–Ω–∞—á–∞–µ—Ç ¬´–Ω–∞–π–¥–∏—Ç–µ —Å–∞–º–∏¬ª.
	if step.Details["task_url"] != "https://sandbox.test/tasks/scan-42" {
		t.Errorf("—Å—Å—ã–ª–∫–∞ –Ω–∞ –∑–∞–¥–∞—á—É = %v", step.Details["task_url"])
	}

	// –ù–∞—Ö–æ–¥–∫–∏ —Å–æ—Ö—Ä–∞–Ω–µ–Ω—ã –∏ –≤–∏–¥–Ω—ã –≤ –∫–∞—Ä—Ç–æ—á–∫–µ.
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("–Ω–∞—Ö–æ–¥–æ–∫ —Å–æ—Ö—Ä–∞–Ω–µ–Ω–æ: %d, –æ–∂–∏–¥–∞–ª–æ—Å—å 2 (%+v)", len(findings), findings)
	}
	// –°–µ—Ä—å—ë–∑–Ω–æ—Å—Ç—å, –∫–æ—Ç–æ—Ä—É—é –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –Ω–µ –ø—Ä–∏—Å–ª–∞–ª–∞, –Ω–µ –ø—Ä–æ–≤–∞–ª–∏–≤–∞–µ—Ç—Å—è –≤ info:
	// –Ω–∞—Ö–æ–¥–∫–∞ –¥–∏–Ω–∞–º–∏—á–µ—Å–∫–æ–≥–æ –∞–Ω–∞–ª–∏–∑–∞ ‚Äî —ç—Ç–æ —Ç–æ, —á—Ç–æ –æ–±—Ä–∞–∑–µ—Ü —Å–¥–µ–ª–∞–ª –ø—Ä–∏ –∑–∞–ø—É—Å–∫–µ.
	bySeverity := map[string]string{}
	for _, f := range findings {
		bySeverity[f.RuleID] = f.Severity
	}
	if bySeverity["Persistence.Cron"] != "high" {
		t.Errorf("—Å–µ—Ä—å—ë–∑–Ω–æ—Å—Ç—å –±–µ–∑ –∑–Ω–∞—á–µ–Ω–∏—è = %q, –æ–∂–∏–¥–∞–ª–æ—Å—å high", bySeverity["Persistence.Cron"])
	}
	if bySeverity["Trojan.Generic"] != "critical" {
		t.Errorf("—Å–µ—Ä—å—ë–∑–Ω–æ—Å—Ç—å –∏–∑ –æ—Ç–≤–µ—Ç–∞ –ø–µ—Å–æ—á–Ω–∏—Ü—ã –ø–æ—Ç–µ—Ä—è–Ω–∞: %q", bySeverity["Trojan.Generic"])
	}

	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || report.State != "findings" || report.FindingsTotal != 2 {
		t.Errorf("–æ—Ç—á—ë—Ç = %+v", report)
	}
}

// TestSandboxUnwantedDoesNotBlock ‚Äî –≤–µ—Ä–¥–∏–∫—Ç UNWANTED –∏–Ω—Ñ–æ—Ä–º–∞—Ü–∏–æ–Ω–Ω—ã–π: –ø–æ–º–µ—Ç–∫–∞ –≤
// –∫–∞—Ä—Ç–æ—á–∫–µ –∏ –≤ –æ—Ç—á—ë—Ç–µ –µ—Å—Ç—å, –ø—É–±–ª–∏–∫–∞—Ü–∏—é –æ–Ω –Ω–µ –¥–µ—Ä–∂–∏—Ç (—Ä–µ—à–µ–Ω–∏–µ –ø–æ–ª—å–∑–æ–≤–∞—Ç–µ–ª—è).
//
// –≠—Ç–æ –∏ –æ—Ç–ª–∏—á–∞–µ—Ç –µ–≥–æ –æ—Ç DANGEROUS: ¬´–Ω–µ–∂–µ–ª–∞—Ç–µ–ª—å–Ω–æ–µ¬ª ‚Äî –Ω–µ ¬´–≤—Ä–µ–¥–æ–Ω–æ—Å–Ω–æ–µ¬ª, –∏
// –∑–≤–∞—Ç—å DevSecOps –Ω–∞ –∫–∞–∂–¥—ã–π –ø–∞–∫–µ—Ç —Å —Ä–µ–∫–ª–∞–º–Ω—ã–º SDK –≤–Ω—É—Ç—Ä–∏ –Ω–µ–∑–∞—á–µ–º.
func TestSandboxUnwantedDoesNotBlock(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictUnwanted, ScanID: "scan-7",
		Detections: []sandbox.Detection{{Name: "Adware.Tracker", Severity: "low"}},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("—Ä–µ–∑—É–ª—å—Ç–∞—Ç = %+v ‚Äî –≤–µ—Ä–¥–∏–∫—Ç UNWANTED –Ω–µ –¥–æ–ª–∂–µ–Ω –¥–µ—Ä–∂–∞—Ç—å –ø—É–±–ª–∏–∫–∞—Ü–∏—é", res)
	}
	if len(e.artifacts.published) != 1 {
		t.Error("–ø–∞–∫–µ—Ç –Ω–µ –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –≤–µ—Ä–¥–∏–∫—Ç–µ UNWANTED")
	}

	steps := stepsByCode(t, r, item.ID)
	// –ò–º–µ–Ω–Ω–æ info, –∞ –Ω–µ pass: ¬´–ø—Ä–æ–π–¥–µ–Ω¬ª —Ä—è–¥–æ–º —Å –Ω–∞—Ö–æ–¥–∫–æ–π —á–∏—Ç–∞–µ—Ç—Å—è –∫–∞–∫ ¬´—á–∏—Å—Ç–æ¬ª.
	if steps["sandbox_scan"].Result != "info" {
		t.Errorf("sandbox_scan = %q, –æ–∂–∏–¥–∞–ª—Å—è info", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "UNWANTED") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –≤–µ—Ä–¥–∏–∫—Ç –Ω–µ –Ω–∞–∑–≤–∞–Ω", stepMessage(steps["sandbox_scan"]))
	}
	// –ù–∞—Ö–æ–¥–∫–∞ –ø—Ä–∏ —ç—Ç–æ–º —Å–æ—Ö—Ä–∞–Ω–µ–Ω–∞: –Ω–µ –±–ª–æ–∫–∏—Ä—É–µ—Ç ‚Äî –Ω–µ –∑–Ω–∞—á–∏—Ç ¬´–Ω–µ –ø–æ–∫–∞–∑—ã–≤–∞–µ–º¬ª.
	findings, err := r.ListCodeFindings(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Errorf("–Ω–∞—Ö–æ–¥–∫–∏ = %+v, –æ–∂–∏–¥–∞–ª–∞—Å—å –æ–¥–Ω–∞", findings)
	}
}

// TestSandboxUnknownVerdictIsNotClean ‚Äî –ø–µ—Å–æ—á–Ω–∏—Ü–∞ –≤–µ—Ä–Ω—É–ª–∞ –∑–Ω–∞—á–µ–Ω–∏–µ, –∫–æ—Ç–æ—Ä–æ–≥–æ
// –º—ã –Ω–µ –∑–Ω–∞–µ–º. –ü—Ä–æ–ø—É—Å—Ç–∏—Ç—å –ø–∞–∫–µ—Ç –ø–æ –≤–µ—Ä–¥–∏–∫—Ç—É, —Å–º—ã—Å–ª–∞ –∫–æ—Ç–æ—Ä–æ–≥–æ –º—ã –Ω–µ –ø–æ–Ω–∏–º–∞–µ–º,
// –Ω–µ–ª—å–∑—è: —ç—Ç–æ —Ç–æ –∂–µ ¬´–ø—Ä–æ–≤–µ—Ä–∫–∞ –Ω–µ –≤—ã–ø–æ–ª–Ω–µ–Ω–∞¬ª.
func TestSandboxUnknownVerdictIsNotClean(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{Verdict: "SUSPICIOUS", ScanID: "scan-9"}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "awaiting_security" {
		t.Fatalf("ItemStatus = %q ‚Äî –Ω–µ–∑–Ω–∞–∫–æ–º—ã–π –≤–µ—Ä–¥–∏–∫—Ç –ø—Ä–æ—á–∏—Ç–∞–Ω –∫–∞–∫ ¬´—á–∏—Å—Ç–æ¬ª", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "warn" {
		t.Errorf("sandbox_scan = %q, –æ–∂–∏–¥–∞–ª—Å—è warn", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SUSPICIOUS") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –Ω–µ–∏–∑–≤–µ—Å—Ç–Ω—ã–π –≤–µ—Ä–¥–∏–∫—Ç –Ω–µ –Ω–∞–∑–≤–∞–Ω, –∏—Å–∫–∞—Ç—å –ø—Ä–∏—á–∏–Ω—É –Ω–µ–≥–¥–µ",
			stepMessage(steps["sandbox_scan"]))
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –Ω–µ–∑–Ω–∞–∫–æ–º–æ–º –≤–µ—Ä–¥–∏–∫—Ç–µ")
	}
}

// TestSandboxReceivesPublishedArtifact ‚Äî –≤ –ø–µ—Å–æ—á–Ω–∏—Ü—É —É—Ö–æ–¥–∏—Ç —Ä–æ–≤–Ω–æ —Ç–æ—Ç —Ñ–∞–π–ª,
// –∫–æ—Ç–æ—Ä—ã–π –±—É–¥–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω, –∞ –Ω–µ –ø–µ—Ä–µ—Å–æ–±—Ä–∞–Ω–Ω—ã–π –∞—Ä—Ö–∏–≤.
//
// –ü—Ä–æ–≤–µ—Ä—è—Ç—å –¥—Ä—É–≥–æ–µ —Å–æ–¥–µ—Ä–∂–∏–º–æ–µ, —á–µ–º —Ç–æ, —á—Ç–æ –ø–æ–µ–¥–µ—Ç —Ä–∞–∑—Ä–∞–±–æ—Ç—á–∏–∫–∞–º, –∑–Ω–∞—á–∏—Ç
// –ø—Ä–æ–≤–µ—Ä—è—Ç—å –Ω–µ —Ç–æ: –∏–º–µ–Ω–Ω–æ —ç—Ç–æ –∏ –æ—Ç–ª–∏—á–∞–µ—Ç —à–∞–≥ –æ—Ç CI-–≤–µ—Ä—Å–∏–∏, –∫–æ—Ç–æ—Ä–∞—è –æ—Ç–ø—Ä–∞–≤–ª—è–ª–∞
// tar.gz –≤—Å–µ–≥–æ –ø—Ä–æ–µ–∫—Ç–∞, —Å–æ–±—Ä–∞–Ω–Ω—ã–π –¥–∂–æ–±–æ–π.
func TestSandboxReceivesPublishedArtifact(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if e.sandbox.calls != 1 {
		t.Fatalf("–æ–±—Ä–∞—â–µ–Ω–∏–π –∫ –ø–µ—Å–æ—á–Ω–∏—Ü–µ: %d, –æ–∂–∏–¥–∞–ª–æ—Å—å 1", e.sandbox.calls)
	}
	artifact, err := r.CurrentArtifact(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.sandbox.lastFile != artifact.Filename {
		t.Errorf("–≤ –ø–µ—Å–æ—á–Ω–∏—Ü—É —É—à—ë–ª —Ñ–∞–π–ª %q, –∞ –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω %q",
			e.sandbox.lastFile, artifact.Filename)
	}
	if artifact.SizeBytes == nil || int64(e.sandbox.lastSize) != *artifact.SizeBytes {
		t.Errorf("–≤ –ø–µ—Å–æ—á–Ω–∏—Ü—É —É—à–ª–æ %d –±–∞–π—Ç, —Ä–∞–∑–º–µ—Ä –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–∞ %v",
			e.sandbox.lastSize, artifact.SizeBytes)
	}
}

// TestDisabledScanIsExplicit ‚Äî –≤—ã–∫–ª—é—á–µ–Ω–Ω—ã–π —à–∞–≥ –æ—Ç–¥–∞—ë—Ç pass —Å —è–≤–Ω–æ–π –ø–æ–º–µ—Ç–∫–æ–π, –∞
// –Ω–µ –º–æ–ª—á–∞ –ø—Ä–æ–ø—É—Å–∫–∞–µ—Ç—Å—è, –∏ –æ—Ç—á—ë—Ç–∞ –Ω–µ –ø–∏—à–µ—Ç: –ø—Ä–æ–≥–æ–Ω–∞ –Ω–µ –±—ã–ª–æ.
func TestDisabledScanIsExplicit(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.config.SandboxEnabled = false
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	if steps["sandbox_scan"].Result != "pass" {
		t.Fatalf("sandbox_scan = %q", steps["sandbox_scan"].Result)
	}
	if !strings.Contains(stepMessage(steps["sandbox_scan"]), "SANDBOX_ENABLED") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –Ω–µ –Ω–∞–∑–≤–∞–Ω–∞ –Ω–∞—Å—Ç—Ä–æ–π–∫–∞, –∫–æ—Ç–æ—Ä–æ–π —à–∞–≥ –≤—ã–∫–ª—é—á–µ–Ω",
			stepMessage(steps["sandbox_scan"]))
	}
	if e.sandbox.calls != 0 {
		t.Error("–≤—ã–∫–ª—é—á–µ–Ω–Ω–∞—è –ø—Ä–æ–≤–µ—Ä–∫–∞ –≤—Å—ë-—Ç–∞–∫–∏ –æ–±—Ä–∞—Ç–∏–ª–∞—Å—å –≤ –ø–µ—Å–æ—á–Ω–∏—Ü—É")
	}
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if report != nil {
		t.Error("–¥–ª—è –≤—ã–∫–ª—é—á–µ–Ω–Ω–æ–≥–æ —à–∞–≥–∞ –∑–∞–ø–∏—Å–∞–Ω –æ—Ç—á—ë—Ç ‚Äî –ø—Ä–æ–≥–æ–Ω–∞ –Ω–µ –±—ã–ª–æ")
	}
}

// TestRetiredStepsDoNotRun ‚Äî —Å–Ω—è—Ç—ã–µ —à–∞–≥–∏ –Ω–µ –≤—ã–ø–æ–ª–Ω—è—é—Ç—Å—è.
//
// –ù–∞—Å—Ç—Ä–æ–π–∫–∏ –∏ —Å–∞–º–∏ —à–∞–≥–∏ –æ—Å—Ç–∞–≤–ª–µ–Ω—ã (pipeline.RetiredSteps), –∏ –±–µ–∑ —ç—Ç–æ–π –ø—Ä–æ–≤–µ—Ä–∫–∏
// –≤–∫–ª—é—á—ë–Ω–Ω—ã–π –ø–æ –Ω–µ–¥–æ—Å–º–æ—Ç—Ä—É BANNER_SCAN_ENABLED –≤–µ—Ä–Ω—É–ª –±—ã —à–∞–≥ –≤ —Å—Ç—Ä–æ–π –º–æ–ª—á–∞.
func TestRetiredStepsDoNotRun(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// –ù–∞—Å—Ç—Ä–æ–π–∫–∏ —Å–Ω—è—Ç—ã—Ö —à–∞–≥–æ–≤ –≤–∫–ª—é—á–µ–Ω—ã, —Å–∫–∞–Ω–µ—Ä—ã –≥–æ—Ç–æ–≤—ã —á—Ç–æ-—Ç–æ –Ω–∞–π—Ç–∏.
	e.config.BannerScanEnabled = true
	e.config.SASTEnabled = true
	e.banner.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "yara", RuleID: "banner", Severity: "high"}}}
	e.sast.outcome = scanners.Outcome{Available: true, Detail: "1",
		Findings: []scanners.Finding{{Scanner: "semgrep", RuleID: "exec", Severity: "high"}}}

	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("—Ä–µ–∑—É–ª—å—Ç–∞—Ç = %+v ‚Äî —Å–Ω—è—Ç—ã–π —à–∞–≥ –∑–∞–¥–µ—Ä–∂–∞–ª –ø—É–±–ª–∏–∫–∞—Ü–∏—é", res)
	}
	if e.banner.calls != 0 || e.sast.calls != 0 {
		t.Errorf("—Å–Ω—è—Ç—ã–µ —Å–∫–∞–Ω–µ—Ä—ã –≤—ã–∑–≤–∞–Ω—ã: banner=%d sast=%d", e.banner.calls, e.sast.calls)
	}
	steps := stepsByCode(t, r, item.ID)
	for _, code := range []string{"banner_scan", "sast_scan"} {
		if _, ok := steps[code]; ok {
			t.Errorf("—Å–Ω—è—Ç—ã–π —à–∞–≥ %s –≤—ã–ø–æ–ª–Ω–µ–Ω –∏ –∑–∞–ø–∏—Å–∞–Ω –≤ –∏—Å—Ç–æ—Ä–∏—é –ø—Ä–æ–≥–æ–Ω–∞", code)
		}
	}
}

// TestReportFilesAreStored ‚Äî –æ—Ç—á—ë—Ç—ã –ø–æ–ø–∞–¥–∞—é—Ç –≤ —Ö—Ä–∞–Ω–∏–ª–∏—â–µ –æ–±–æ–∏–º–∏ —Ñ–æ—Ä–º–∞—Ç–∞–º–∏ –∏
// —Å–æ–¥–µ—Ä–∂–∞—Ç —Ç–æ, —á—Ç–æ –Ω—É–∂–Ω–æ –¥–ª—è —Ä–∞–∑–±–æ—Ä–∞.
func TestReportFilesAreStored(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-1",
		Detections: []sandbox.Detection{{
			Name: "Backdoor.Python.Exec", Type: "malware", Severity: "high",
			Details: "–∑–∞–ø—É—Å–∫ —Å—Ç–æ—Ä–æ–Ω–Ω–µ–≥–æ –∫–æ–¥–∞ –ø—Ä–∏ –∏–º–ø–æ—Ä—Ç–µ",
		}},
	}
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("Run: %v", err)
	}

	row, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatal("—Å—Ç—Ä–æ–∫–∞ –æ—Ç—á—ë—Ç–∞ –Ω–µ –∑–∞–ø–∏—Å–∞–Ω–∞")
	}
	if row.State != "findings" || row.FindingsBlocking != 1 {
		t.Errorf("—Å–≤–æ–¥–∫–∞ –æ—Ç—á—ë—Ç–∞ = %+v", row)
	}
	if row.JSONKey != storage.ReportKey(item.ID, "sandbox_scan", "json") {
		t.Errorf("JSONKey = %q", row.JSONKey)
	}
	// –û—Ç—á—ë—Ç –ª–µ–∂–∏—Ç –≤ –°–í–û–Å–ú —Ö—Ä–∞–Ω–∏–ª–∏—â–µ, –∞ –Ω–µ —Ä—è–¥–æ–º —Å –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–æ–º: –∞—Ä—Ç–µ—Ñ–∞–∫—Ç
	// –≤—ã—á–∏—â–∞–µ—Ç—Å—è –∏–∑ –ø—Ä–æ–º–µ–∂—É—Ç–æ—á–Ω–æ–π –∑–æ–Ω—ã, –æ—Ç—á—ë—Ç –æ–±—è–∑–∞–Ω —ç—Ç–æ –ø–µ—Ä–µ–∂–∏—Ç—å.
	if row.Bucket == nil || *row.Bucket != e.reports.Bucket() {
		t.Errorf("—Ä–µ–ø–æ–∑–∏—Ç–æ—Ä–∏–π –æ—Ç—á—ë—Ç–∞ = %v, –æ–∂–∏–¥–∞–ª—Å—è %q", row.Bucket, e.reports.Bucket())
	}

	jsonBody, err := e.reports.Get(ctx, row.JSONKey)
	if err != nil {
		t.Fatalf("JSON-–æ—Ç—á—ë—Ç –Ω–µ –Ω–∞–π–¥–µ–Ω –≤ —Ö—Ä–∞–Ω–∏–ª–∏—â–µ: %v", err)
	}
	var report reports.Report
	if err := json.Unmarshal(jsonBody, &report); err != nil {
		t.Fatalf("JSON-–æ—Ç—á—ë—Ç –Ω–µ —Ä–∞–∑–±–∏—Ä–∞–µ—Ç—Å—è: %v", err)
	}
	if report.Package.Name != pkg.Name || report.Summary.Blocking != 1 {
		t.Errorf("—Å–æ–¥–µ—Ä–∂–∏–º–æ–µ –æ—Ç—á—ë—Ç–∞ = %+v", report.Summary)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "Backdoor.Python.Exec" {
		t.Errorf("–Ω–∞—Ö–æ–¥–∫–∏ –≤ –æ—Ç—á—ë—Ç–µ = %+v", report.Findings)
	}
	// sha256 –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–∞ –≤ –æ—Ç—á—ë—Ç–µ ‚Äî –ø–æ –Ω–µ–º—É –æ—Ç—á—ë—Ç —Å–≤—è–∑—ã–≤–∞–µ—Ç—Å—è —Å –∫–æ–Ω–∫—Ä–µ—Ç–Ω—ã–º–∏ –±–∞–π—Ç–∞–º–∏.
	if report.Package.SHA256 == "" {
		t.Error("sha256 –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–∞ –æ—Ç—Å—É—Ç—Å—Ç–≤—É–µ—Ç –≤ –æ—Ç—á—ë—Ç–µ")
	}

	htmlBody, err := e.reports.Get(ctx, row.HTMLKey)
	if err != nil {
		t.Fatalf("HTML-–æ—Ç—á—ë—Ç –Ω–µ –Ω–∞–π–¥–µ–Ω: %v", err)
	}
	if !strings.Contains(string(htmlBody), "Backdoor.Python.Exec") {
		t.Error("–Ω–∞—Ö–æ–¥–∫–∞ –æ—Ç—Å—É—Ç—Å—Ç–≤—É–µ—Ç –≤ HTML-–æ—Ç—á—ë—Ç–µ")
	}
}

// TestReportSurvivesRerun ‚Äî –ø–æ–≤—Ç–æ—Ä–Ω—ã–π –ø—Ä–æ–≥–æ–Ω –æ–±–Ω–æ–≤–ª—è–µ—Ç –æ—Ç—á—ë—Ç, –∞ –Ω–µ –ø–ª–æ–¥–∏—Ç —Å—Ç—Ä–æ–∫–∏.
func TestReportSurvivesRerun(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)

	if _, err := pipeline.Run(ctx, pc, ""); err != nil {
		t.Fatalf("–ø–µ—Ä–≤—ã–π –ø—Ä–æ–≥–æ–Ω: %v", err)
	}
	first, _ := r.GetScanReport(ctx, item.ID, "sandbox_scan")

	// –í—Ç–æ—Ä–æ–π –ø—Ä–æ–≥–æ–Ω ‚Äî –ø–µ—Å–æ—á–Ω–∏—Ü–∞ —Ç–µ–ø–µ—Ä—å —á—Ç–æ-—Ç–æ –Ω–∞—à–ª–∞.
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-2",
		Detections: []sandbox.Detection{{Name: "Trojan.Generic", Severity: "critical"}},
	}
	pc2 := e.context(pkg, ver, item)
	if _, err := pipeline.Run(ctx, pc2, "download"); err != nil {
		t.Fatalf("–≤—Ç–æ—Ä–æ–π –ø—Ä–æ–≥–æ–Ω: %v", err)
	}

	second, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Errorf("—Å–æ–∑–¥–∞–Ω –Ω–æ–≤—ã–π –æ—Ç—á—ë—Ç –≤–º–µ—Å—Ç–æ –æ–±–Ω–æ–≤–ª–µ–Ω–∏—è: %d -> %d", first.ID, second.ID)
	}
	if second.State != "findings" {
		t.Errorf("–æ—Ç—á—ë—Ç –Ω–µ –æ–±–Ω–æ–≤–∏–ª—Å—è: %+v", second)
	}
	all, err := r.ListScanReports(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("–æ—Ç—á—ë—Ç–æ–≤: %d, –æ–∂–∏–¥–∞–ª—Å—è 1 (–ø–æ –æ–¥–Ω–æ–º—É –Ω–∞ —à–∞–≥ —Å–∫–∞–Ω–∏—Ä–æ–≤–∞–Ω–∏—è)", len(all))
	}
}

// --------------------------------------------------------------------- —Ä–µ—à–µ–Ω–∏–µ DevSecOps

// TestSecurityOverrideUnblocksAllScanSteps ‚Äî –±–µ–∑ —ç—Ç–æ–≥–æ –≤–æ–∑–æ–±–Ω–æ–≤–ª—ë–Ω–Ω—ã–π –ø–æ—Å–ª–µ
// –æ–¥–æ–±—Ä–µ–Ω–∏—è –∫–æ–Ω–≤–µ–π–µ—Ä —Å–Ω–æ–≤–∞ —É–ø—ë—Ä—Å—è –±—ã –≤ —Ç–æ—Ç –∂–µ –≤–µ—Ä–¥–∏–∫—Ç –∏ –≤–µ—Ä–Ω—É–ª –ø–∞–∫–µ—Ç –≤
// –æ—á–µ—Ä–µ–¥—å: —Ä–µ—à–µ–Ω–∏–µ DevSecOps –Ω–µ –∏–º–µ–ª–æ –±—ã —ç—Ñ—Ñ–µ–∫—Ç–∞.
func TestSecurityOverrideUnblocksAllScanSteps(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	// –í—Å—ë —Å—Ä–∞–∑—É –ø—Ä–æ—Ç–∏–≤ –ø–∞–∫–µ—Ç–∞: —É—è–∑–≤–∏–º–æ—Å—Ç—å –≤—ã—à–µ –ø–æ—Ä–æ–≥–∞ –∏ –≤–µ—Ä–¥–∏–∫—Ç –ø–µ—Å–æ—á–Ω–∏—Ü—ã.
	e.sandbox.result = sandbox.Result{
		Verdict: sandbox.VerdictDangerous, ScanID: "scan-13",
		Detections: []sandbox.Detection{{Name: "Trojan.Generic", Severity: "critical"}},
	}

	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	e.index.Records = []osv.Record{criticalRecord(t, pkg.Name)}

	if _, err := pipeline.Run(ctx, e.context(pkg, ver, item), ""); err != nil {
		t.Fatalf("–ø–µ—Ä–≤—ã–π –ø—Ä–æ–≥–æ–Ω: %v", err)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –æ—Ç–∫—Ä—ã—Ç—ã—Ö –±–ª–æ–∫–∏—Ä–æ–≤–∫–∞—Ö")
	}

	// DevSecOps —Ä–∞–∑—Ä–µ—à–∞–µ—Ç –ø—É–±–ª–∏–∫–∞—Ü–∏—é.
	user, err := r.GetOrCreateUser(ctx, "sec.petrov", "–ü—ë—Ç—Ä –ü–µ—Ç—Ä–æ–≤")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetSecurityOverride(ctx, ver.ID, user.ID, "–ü—Ä–æ–≤–µ—Ä–µ–Ω–æ –≤—Ä—É—á–Ω—É—é, –ª–æ–∂–Ω—ã–µ —Å—Ä–∞–±–∞—Ç—ã–≤–∞–Ω–∏—è"); err != nil {
		t.Fatalf("SetSecurityOverride: %v", err)
	}
	fresh, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}

	// –ö–æ–Ω–≤–µ–π–µ—Ä –≤–æ–∑–æ–±–Ω–æ–≤–ª—è–µ—Ç—Å—è —Å —à–∞–≥–∞ —Å–∫–∞—á–∏–≤–∞–Ω–∏—è ‚Äî –∫–∞–∫ —ç—Ç–æ –¥–µ–ª–∞–µ—Ç decide_security.
	pc := e.context(pkg, fresh, item)
	res, err := pipeline.Run(ctx, pc, "download")
	if err != nil {
		t.Fatalf("–≤–æ–∑–æ–±–Ω–æ–≤–ª–µ–Ω–∏–µ: %v", err)
	}
	if !res.Terminal || res.ItemStatus != "approved" {
		t.Fatalf("—Ä–µ–∑—É–ª—å—Ç–∞—Ç = %+v, —Ä–µ—à–µ–Ω–∏–µ DevSecOps –Ω–µ —Å—Ä–∞–±–æ—Ç–∞–ª–æ", res)
	}
	if len(e.artifacts.published) != 1 {
		t.Error("–ø–∞–∫–µ—Ç –Ω–µ –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø–æ—Å–ª–µ —Ä–∞–∑—Ä–µ—à–µ–Ω–∏—è DevSecOps")
	}

	steps := stepsByCode(t, r, item.ID)
	for _, code := range pipeline.SecurityBlockers {
		if steps[code].Result != "pass" {
			t.Errorf("—à–∞–≥ %s = %q, —Ä–µ—à–µ–Ω–∏–µ DevSecOps –¥–æ–ª–∂–Ω–æ –∑–∞–∫—Ä—ã–≤–∞—Ç—å –±–ª–æ–∫–∏—Ä–æ–≤–∫–∏ "+
				"–ø–æ —Å–æ–¥–µ—Ä–∂–∏–º–æ–º—É —Å—Ä–∞–∑—É", code, steps[code].Result)
		}
	}
	// –ò–º—è –ø—Ä–∏–Ω—è–≤—à–µ–≥–æ —Ä–µ—à–µ–Ω–∏–µ –ø–æ–ø–∞–ª–æ –≤ –æ—Ç—á—ë—Ç: –±–µ–∑ —ç—Ç–æ–≥–æ –Ω–∞—Ö–æ–¥–∫–∏ –ø–µ—Å–æ—á–Ω–∏—Ü—ã
	// –≤—ã–≥–ª—è–¥–µ–ª–∏ –±—ã –ø—Ä–æ—Å—Ç–æ –ø—Ä–æ–∏–≥–Ω–æ—Ä–∏—Ä–æ–≤–∞–Ω–Ω—ã–º–∏.
	report, err := r.GetScanReport(ctx, item.ID, "sandbox_scan")
	if err != nil {
		t.Fatal(err)
	}
	jsonBody, err := e.reports.Get(ctx, report.JSONKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonBody), "–ü—ë—Ç—Ä –ü–µ—Ç—Ä–æ–≤") {
		t.Error("—Ä–µ—à–µ–Ω–∏–µ DevSecOps –Ω–µ –æ—Ç—Ä–∞–∂–µ–Ω–æ –≤ –æ—Ç—á—ë—Ç–µ ‚Äî –Ω–∞—Ö–æ–¥–∫–∏ –≤—ã–≥–ª—è–¥–µ–ª–∏ –±—ã –ø—Ä–æ–∏–≥–Ω–æ—Ä–∏—Ä–æ–≤–∞–Ω–Ω—ã–º–∏")
	}
}

// --------------------------------------------------------------------- —à–∞–≥ 8

func TestPublishBlockedByOpenLicense(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")
	pc := e.context(pkg, ver, item)
	pc.Lic = licensePolicy()

	if _, err := pipeline.Run(ctx, pc, ""); err != nil {
		t.Fatalf("Run: %v", err)
	}
	steps := stepsByCode(t, r, item.ID)
	msg := *steps["publish"].Message
	if !strings.Contains(msg, "–ü—É–±–ª–∏–∫–∞—Ü–∏—è –æ—Ç–ª–æ–∂–µ–Ω–∞") || !strings.Contains(msg, "—é—Ä–∏—Å—Ç–æ–≤") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ publish = %q", msg)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–ø–∞–∫–µ—Ç –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø—Ä–∏ –æ—Ç–∫—Ä—ã—Ç–æ–π –±–ª–æ–∫–∏—Ä–æ–≤–∫–µ –ª–∏—Ü–µ–Ω–∑–∏–∏")
	}
}

// TestPublishRefusesCancelledItem ‚Äî –∑–∞—è–≤–∫—É –∑–∞–∫—Ä—ã–ª–∏, –ø–æ–∫–∞ —à—ë–ª –ø—Ä–æ–≥–æ–Ω: –ø–∞–∫–µ—Ç –Ω–µ
// –ø—É–±–ª–∏–∫—É–µ—Ç—Å—è.
//
// –û—Ç–º–µ–Ω–∞ –∏ —Ç–∞–∫ —Å–Ω–∏–º–∞–µ—Ç –ø–∞–∫–µ—Ç —Å –æ–±—Ä–∞–±–æ—Ç–∫–∏ (–≤–æ—Ä–∫–µ—Ä –≤–∏–¥–∏—Ç –ø–æ –æ—Ç–º–µ—Ç–∫–µ –æ –∂–∏–∑–Ω–∏,
// —á—Ç–æ —Å—Ç—Ä–æ–∫—É ¬´–æ—Ç–æ–±—Ä–∞–ª–∏¬ª), –Ω–æ –æ—Ç–º–µ—Ç–∫–∞ —Ä–µ–¥–∫–∞—è ‚Äî —Ä–∞–∑ –≤ 30 —Å–µ–∫—É–Ω–¥, ‚Äî –∏ –ø—É–±–ª–∏–∫–∞—Ü–∏—è
// –º–æ–≥–ª–∞ –±—ã –ø—Ä–æ—Å–∫–æ—á–∏—Ç—å –≤ —ç—Ç–æ—Ç –∑–∞–∑–æ—Ä. –ü—É–±–ª–∏–∫–∞—Ü–∏—è ‚Äî –∑–∞–ø–∏—Å—å –≤–æ –≤–Ω–µ—à–Ω–∏–π
// –∞—Ä—Ç–µ—Ñ–∞–∫—Ç–æ—Ä–∏, –µ—ë –ø–æ—Ç–æ–º –Ω–µ –æ—Ç–æ–∑–≤–∞—Ç—å –æ–¥–Ω–∏–º UPDATE, –ø–æ—ç—Ç–æ–º—É —à–∞–≥ –ø—Ä–æ–≤–µ—Ä—è–µ—Ç
// —Å—Ç–∞—Ç—É—Å –∑–∞–Ω–æ–≤–æ —Å–∞–º.
func TestPublishRefusesCancelledItem(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	// –û—Ç–º–µ–Ω–∞ –ø—Ä–∏—Ö–æ–¥–∏—Ç –ø–æ—Å–ª–µ –∑–∞—Ö–≤–∞—Ç–∞: pc.Item ‚Äî —Å–Ω–∏–º–æ–∫, –≤ –Ω—ë–º –µ—ë –Ω–µ –≤–∏–¥–Ω–æ.
	pc := e.context(pkg, ver, item)
	if _, err := r.Pool().Exec(ctx,
		`UPDATE request_item SET status = 'cancelled' WHERE id = $1`, item.ID); err != nil {
		t.Fatal(err)
	}

	res, err := pipeline.Run(ctx, pc, "publish")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(e.artifacts.published) != 0 {
		t.Fatal("–æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω –ø–∞–∫–µ—Ç –∏–∑ –∑–∞–∫—Ä—ã—Ç–æ–π –∑–∞—è–≤–∫–∏")
	}
	if res.ItemStatus != "cancelled" {
		t.Errorf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è cancelled", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	if !strings.Contains(stepMessage(steps["publish"]), "–∑–∞–∫—Ä—ã—Ç–∞ –∞–≤—Ç–æ—Ä–æ–º") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ publish = %q ‚Äî –≤ –∫–∞—Ä—Ç–æ—á–∫–µ –¥–æ–ª–∂–Ω–æ –±—ã—Ç—å –≤–∏–¥–Ω–æ, –ø–æ—á–µ–º—É –Ω–µ –æ–ø—É–±–ª–∏–∫–æ–≤–∞–ª–∏",
			stepMessage(steps["publish"]))
	}
}

func TestDryRunDoesNotApprove(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.artifacts.dryRun = true
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// –ü—É–±–ª–∏–∫–∞—Ü–∏–∏ –Ω–µ –±—ã–ª–æ ‚Äî –ø–∞–∫–µ—Ç –Ω–µ –æ–¥–æ–±—Ä–µ–Ω, –∏–Ω–∞—á–µ –∫–æ–º–∞–Ω–¥–∞ —É—Å—Ç–∞–Ω–æ–≤–∫–∏ –≤–µ–ª–∞ –±—ã
	// –≤ –Ω–∏–∫—É–¥–∞.
	if res.ItemStatus != "dry_run" {
		t.Errorf("ItemStatus = %q, –æ–∂–∏–¥–∞–ª—Å—è dry_run", res.ItemStatus)
	}
	if len(e.artifacts.published) != 0 {
		t.Error("–≤ —Ä–µ–∂–∏–º–µ dry-run —á—Ç–æ-—Ç–æ –æ–ø—É–±–ª–∏–∫–æ–≤–∞–Ω–æ")
	}
	got, err := r.GetPackageVersion(ctx, ver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == "approved" {
		t.Error("–≤–µ—Ä—Å–∏—è –ø–æ–º–µ—á–µ–Ω–∞ –æ–¥–æ–±—Ä–µ–Ω–Ω–æ–π –±–µ–∑ –ø—É–±–ª–∏–∫–∞—Ü–∏–∏")
	}
}

func TestPublishFailureIsReported(t *testing.T) {
	r, cleanup := mustRepo(t)
	defer cleanup()
	ctx := context.Background()

	e := newEnv(t, r)
	e.artifacts.publishErr = errors.New("Deploy denied: repository is moderated")
	pkg, ver, item := setup(t, r, "pkg", "1.0.0")

	res, err := pipeline.Run(ctx, e.context(pkg, ver, item), "")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ItemStatus != "failed" {
		t.Fatalf("ItemStatus = %q", res.ItemStatus)
	}
	steps := stepsByCode(t, r, item.ID)
	// –†–æ–≤–Ω–æ —ç—Ç–æ—Ç –æ—Ç–≤–µ—Ç –æ—Ç–ª–∏—á–∞–µ—Ç ¬´–ø—Ä—è–º–æ–π PUT –∑–∞–ø—Ä–µ—â—ë–Ω¬ª –æ—Ç ¬´–Ω–µ—Ç –ø—Ä–∞–≤¬ª ‚Äî –æ—Ç–∫—Ä—ã—Ç—ã–π
	// –≤–æ–ø—Ä–æ—Å –ø—Ä–æ –±–æ–µ–≤–æ–π Artifactory (docs/ci-parity-gaps.md).
	if !strings.Contains(*steps["publish"].Message, "repository is moderated") {
		t.Errorf("—Å–æ–æ–±—â–µ–Ω–∏–µ = %q ‚Äî –æ—Ç–≤–µ—Ç –∞€û9⁄⁄$z{-ÆÈ‹j◊ù(%Ù§(%¡±’ù•∏∞Åï…»ÄËÙÅ»πï–†âµÖŸï∏à§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%…ïò∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄâÖπë…Ω•ë‡πÖππΩ—Ö—•Ω∏ÈÖππΩ—Ö—•Ω∏Ëƒ∏‰∏ƒà§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%µï—Ñ∞Åï…»ÄËÙÅ¡±’ù•∏πï—ç°5ï—ÖëÖ—Ñ°çΩπ—ï·–π	Öç≠ù…Ω’πê†§∞Å…ïò§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö±ò†âπë…Ω•ë`ÉB˜B‘ÉB˜B√BÁB”B◊BÙÉBÀB¯ÉBÀFB˚FB˚BÉFB◊BˇB˚BﬂB„FB˚FB„B‡ËÄïÿà∞Åï…»§(%Ù(%•òÄÖÕ—…•πùÃπ!ÖÕA…ïô•‡°µï—Ñπ…—•ôÖç—UI0∞Äâ°——¡ÃËºΩùΩΩù±îµµÖŸï∏π—ïÕ–ºà§ÅÏ($%–π……Ω…ò†ãB√FFB◊FB√BÎFÉBÀBﬂF?FÉB˜B‘ÉB„B‹ÅΩΩù±îÅ5ÖŸï∏ËÄïÃà∞Åµï—Ñπ…—•ôÖç—UI0§(%Ù)Ù((ººÅQïÕ—A!A5ï—ÖëÖ—ÑÉäPÅAÖç≠Öù•Õ–ÉB˚FB”B√FGFÉB”B„FFFB„B«FFB„B»∞ÉB”B√FFÉB‡ÉBÔB„FB◊B˜BﬂB„F8ÉB˚B”B˜B„B(ººÉB˚FBÀB◊FB˚BÏÉBˇB˚BÔB‘ÅÕ°ÖÕ’¥ÉFB˚B”B◊FB€B„FÅÕ°Ñƒ∞ÉB¿ÉB˜B‘ÅÕ°Ñ»‘ÿ∞ÉB˜B◊FBÛB˚FFF<ÉB˜B¿ÉB„BÛF<∏)ô’πåÅQïÕ—A!A5ï—ÖëÖ—Ñ°–Ä©—ïÕ—•πúπP§ÅÏ(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩ¡Öç≠Öù•Õ–π—ïÕ–Ω¿»ΩÕÂµôΩπ‰ΩçΩπÕΩ±îπ©ÕΩ∏àËÅÅÏâ¡Öç≠ÖùïÃàÈÏâÕÂµôΩπ‰ΩçΩπÕΩ±îàÈl($$%ÏâŸï…Õ•Ω∏àËâÿÿ∏–∏»à∞âŸï…Õ•Ωπ}πΩ…µÖ±•ÈïêàËàÿ∏–∏»∏¿à∞â—•µîàËà»¿»Ã¥ƒ»¥ƒ¡P¿‡Ë¿¿Ë¿¿¨¿¿Ë¿¿à∞($$$Äâ±•çïπÕîàÈlâ5%Pât∞($$$Äâë•Õ–àÈÏâ—Â¡îàËâÈ•¿à∞â’…∞àËâ°——¡ÃËºΩÖ¡§πù•—°’àπ—ïÕ–Ω…ï¡ΩÃΩÕÂµôΩπ‰ΩçΩπÕΩ±îΩÈ•¡âÖ±∞ΩÖâåà∞($$$ÄÄÄÄÄÄÄÄÄâÕ°ÖÕ’¥àËàƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒƒâııuııÄ∞(%ıÙ((%µï—ÑÄËÙÅµï—ÖΩ»°–∞Äâ¡°¿à∞ÄâÕÂµôΩπ‰ΩçΩπÕΩ±îËÿ∏–∏»à∞Åò§(%•òÅµï—Ñπ1•çïπÕïMA`ÄÑÙÄâ5%PàÅÏ($%–π……Ω…ò†ãBÔB„FB◊B˜BﬂB„F<ÄÙÄïƒà∞Åµï—Ñπ1•çïπÕïMA`§(%Ù(%•òÅµï—Ñπ°ïç≠Õ’µ±ùºÄÑÙÄâÕ°ÑƒàÅÏ($%–π……Ω…ò†ãB√BÔBœB˚FB„FBÉFFBÛBÛF,ÄÙÄïƒËÅAÖç≠Öù•Õ–ÉB˜B√BﬂF/BÀB√B◊FÉBˇB˚BÔB‘ÅÕ°ÖÕ’¥∞ÉB¿ÉBÎBÔB√B”FGFÉB»ÉB˜B◊BœB¯ÅÕ°Ñƒà∞($$%µï—Ñπ°ïç≠Õ’µ±ùº§(%Ù(%•òÅµï—ÑπA’â±•Õ°ïë–ÄÙÙÅπ•∞ÅÒÅµï—ÑπA’â±•Õ°ïë–πΩ…µÖ–†à»¿¿ÿ¥¿ƒ¥¿»à§ÄÑÙÄà»¿»Ã¥ƒ»¥ƒ¿àÅÏ($%–π……Ω…ò†ãB”B√FB¿ÉBˇFB«BÔB„BÎB√FB„B‡ÄÙÄïÿà∞Åµï—ÑπA’â±•Õ°ïë–§(%Ù(%•òÄÖÕ—…•πùÃπ!ÖÕM’ôô•‡°µï—Ñπ…—•ôÖç—•±ïπÖµî∞ÄàπÈ•¿à§ÅÏ($%–π……Ω…ò†ãB„BÛF<ÉFB√BÁBÔB¿ÄÙÄïƒà∞Åµï—Ñπ…—•ôÖç—•±ïπÖµî§(%Ù)Ù((ººÅQïÕ—A!AYï…Õ•Ωπ]•—°1ïÖë•πùXÉäPÅÿÿ∏–∏»ÉB‡Äÿ∏–∏»ÉF7FB¯ÉB˚B”B˜B¿ÉBÀB◊FFB„F<∏ÉBÉB√BﬂBÀB˚B”B„FF0ÉB„F(ººÉBˇB¯ÉB”BÀFBÉFFFB˚BÎB√BÉB»ÉB«B√BﬂB‘ÉBﬂB˜B√FB„BÔB¯ÉB«F,ÉBÛB˚B”B◊FB„FB˚BÀB√FF0ÉB˚B”B„BÙÉBˇB√BÎB◊FÉB”BÀB√B€B”F,∏)ô’πåÅQïÕ—A!AYï…Õ•Ωπ]•—°1ïÖë•πùX°–Ä©—ïÕ—•πúπP§ÅÏ(%¡±’ù•∏ÄËÙÅ¡±’ù•π]•—†°–∞Äâ¡°¿à∞ÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÌıÙ§(%›•—°X∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄâÕÂµôΩπ‰ΩçΩπÕΩ±îÈÿÿ∏–∏»à§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%¡±Ö•∏∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄâÕÂµôΩπ‰ΩçΩπÕΩ±îËÿ∏–∏»à§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%•òÅ›•—°XπYï…Õ•Ω∏ÄÑÙÅ¡±Ö•∏πYï…Õ•Ω∏ÅÏ($%–π……Ω…ò†âÿÿ∏–∏»ÉäHÄïƒ∞ÉB¿Äÿ∏–∏»ÉäHÄïƒËÉB˚B”B„BÙÉBˇB√BÎB◊FÉFB◊FB√BÏÉB«F,ÉB»ÉB”BÀB‘ÉFFFB˚BÎB‡ÉB«B√BﬂF,à∞($$%›•—°XπYï…Õ•Ω∏∞Å¡±Ö•∏πYï…Õ•Ω∏§(%Ù($ººÉBwB√BˇB„FB√B˜B˜B˚B‘ÉBˇB˚BÔF3BﬂB˚BÀB√FB◊BÔB◊BÉBˇFB‡ÉF7FB˚BÉFB˚FFB√B˜F?B◊FFF<ËÉB»ÉBÎB√FFB˚FBÎB‘ÉB˚BÙÉB”B˚BÔB€B◊BÙ($ººÉBÀB„B”B◊FF0ÉFBÀB˚F8ÉBﬂB√BˇB„FF0∞ÉB¿ÉB˜B‘ÉBˇFB„BÀB◊B”FGB˜B˜FF8ÉBËÉBÎB√B˜B˚B˜F∏(%•òÅ›•—°XπIÖ›Yï…Õ•Ω∏ÄÑÙÄâÿÿ∏–∏»àÅÏ($%–π……Ω…ò†ãB„FFB˚B”B˜B√F<ÉBﬂB√BˇB„FF0ÉBÀB◊FFB„B‡ÉBˇB˚FB◊FF?B˜B¿ËÄïƒà∞Å›•—°XπIÖ›Yï…Õ•Ω∏§(%Ù)Ù((ººÅQïÕ—ΩπÖπA•ç≠Õ1Ö—ïÕ—IïŸ•Õ•Ω∏ÉäPÉBˇB˚B–ÉB˚B”B˜B˚B‰ÉBÀB◊FFB„B◊B‰ÉFÉFB◊FB◊BˇFB¿ÉB«F/BÀB√B◊FÉB˜B◊FBÎB˚BÔF3BÎB¯(ººÉFB◊BÀB„BﬂB„B‰ÉFÉFB√BﬂB˜F/BÛB‡ÉBˇB√FFB√BÛB‡∞ÉB‡ÉB«B◊FFGFFF<ÉBˇB˚FBÔB◊B”B˜F?F<ÉBˇB¯ÉBÀFB◊BÛB◊B˜B‡∞ÉB¿ÉB˜B‘ÉBˇB◊FBÀB√F<ÉB»(ººÉB˚FBÀB◊FB‘ËÉBˇB˚FF?B”B˚BËÉF7BÔB◊BÛB◊B˜FB˚B»ÉFB◊FBÀB◊F ÉB˜B‘ÉBœB√FB√B˜FB„FFB◊F∏)ô’πåÅQïÕ—ΩπÖπA•ç≠Õ1Ö—ïÕ—IïŸ•Õ•Ω∏°–Ä©—ïÕ—•πúπP§ÅÏ(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩÈ±•àºƒ∏Ã∏ƒΩ|Ω|Ω…ïŸ•Õ•ΩπÃàËÅÅÏâ…ïŸ•Õ•ΩπÃàÈl($$%Ïâ…ïŸ•Õ•Ω∏àËââââââââââââââââàà∞â—•µîàËà»¿»–¥¿Ã¥¿≈Pƒ¿Ë¿¿Ë¿¡hâÙ∞($$%Ïâ…ïŸ•Õ•Ω∏àËâÖÖÖÖÖÖÖÖÖÖÖÖÖÖÖÑà∞â—•µîàËà»¿»–¥¿ƒ¥¿≈Pƒ¿Ë¿¿Ë¿¡hâıuıÄ∞($$â°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩÈ±•àºƒ∏Ã∏ƒΩ|Ω|Ω…ïŸ•Õ•ΩπÃΩâââââââââââââââàΩô•±ïÃàËÅÄ($$%Ïâô•±ïÃàÈÏâçΩπÖπ}ï·¡Ω…–π—ùËàÈÌÙ∞âçΩπÖπµÖπ•ôïÕ–π—·–àÈÌıııÄ∞(%ıÙ((%µï—ÑÄËÙÅµï—ÖΩ»°–∞ÄâçΩπÖ∏à∞ÄâÈ±•àºƒ∏Ã∏ƒà∞Åò§(%•òÄÖÕ—…•πùÃπΩπ—Ö•πÃ°µï—Ñπ…—•ôÖç—UI0∞Äââââââââââââââââàà§ÅÏ($%–π……Ω…ò†ãBÀBﬂF?FB¿ÉB˜B‘ÉBˇB˚FBÔB◊B”B˜F?F<ÉFB◊BÀB„BﬂB„F<ËÄïÃà∞Åµï—Ñπ…—•ôÖç—UI0§(%Ù(%•òÄÖÕ—…•πùÃπΩπ—Ö•πÃ°µï—Ñπ…—•ôÖç—•±ïπÖµî∞Äââââââââââââàà§ÅÏ($%–π……Ω…ò†ãFB◊BÀB„BﬂB„F<ÉB˜B‘ÉBˇB˚BˇB√BÔB¿ÉB»ÉB„BÛF<ÉFB√BÁBÔB¿ËÄïƒÉäPÉBˇB¯ÉB˜B◊BÛFÉB»ÉB√FFB◊FB√BÎFB˚FB‡Äà¨($$$ãBÀB„B”B˜B¯∞ÉBÎB√BÎB˚B‘ÉFB˚B”B◊FB€B„BÛB˚B‘ÉBˇFB˚BÛB˚B”B◊FB„FB˚BÀB√B˜B¯à∞Åµï—Ñπ…—•ôÖç—•±ïπÖµî§(%Ù(%•òÅµï—ÑπA’â±•Õ°ïë–ÄÙÙÅπ•∞ÅÒÅµï—ÑπA’â±•Õ°ïë–πΩ…µÖ–†à»¿¿ÿ¥¿ƒ¥¿»à§ÄÑÙÄà»¿»–¥¿Ã¥¿ƒàÅÏ($%–π……Ω…ò†ãB”B√FB¿ÉBˇFB«BÔB„BÎB√FB„B‡ÄÙÄïÿà∞Åµï—ÑπA’â±•Õ°ïë–§(%Ù)Ù()ô’πåÅQïÕ—ΩπÖπΩ›π±ΩÖë%πç±’ëïÕŸï…ÂIïç•¡ï•±î°–Ä©—ïÕ—•πúπP§ÅÏ(%çΩπÕ–Å…ïŸ•Õ•Ω∏ÄÙÄàƒ»Ã–‘ÿ‹‡‰¡Öâçëïòƒ»Ã–‘ÿ‹‡‰¡Öâçëïòà(%ô•±ïÕUI0ÄËÙÄâ°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩÈ±•àºƒ∏Ã∏ƒΩ|Ω|Ω…ïŸ•Õ•ΩπÃºàÄ¨Å…ïŸ•Õ•Ω∏Ä¨ÄàΩô•±ïÃà(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩÈ±•àºƒ∏Ã∏ƒΩ|Ω|Ω…ïŸ•Õ•ΩπÃàËÅÅÏâ…ïŸ•Õ•ΩπÃàÈl($$%Ïâ…ïŸ•Õ•Ω∏àËâÄÄ¨Å…ïŸ•Õ•Ω∏Ä¨ÅÄà∞â—•µîàËà»¿»ÿ¥¿ƒ¥¿≈Pƒ¿Ë¿¿Ë¿¡hâıuıÄ∞($%ô•±ïÕUI0ËÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÅÅÏâô•±ïÃàÈÏâçΩπÖπ}ï·¡Ω…–π—ùËàÈÌÙ∞âçΩπÖπ}ÕΩ’…çïÃπ—ùËàÈÌÙ∞âçΩπÖπô•±îπ¡‰àÈÌıııÄ∞($%ô•±ïÕUI0Ä¨ÄàΩçΩπÖπ}ï·¡Ω…–π—ùËàËÄÄâï·¡Ω…–à∞($%ô•±ïÕUI0Ä¨ÄàΩçΩπÖπ}ÕΩ’…çïÃπ—ùËàËÄâÕΩ’…çïÃà∞($%ô•±ïÕUI0Ä¨ÄàΩçΩπÖπô•±îπ¡‰àËÄÄÄÄÄÄâ…ïç•¡îà∞(%ıÙ(%¡±’ù•∏ÄËÙÅ¡±’ù•π]•—†°–∞ÄâçΩπÖ∏à∞Åò§(%…ïò∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄâÈ±•àºƒ∏Ã∏ƒà§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%ëΩ›π±ΩÖëï»∞ÅΩ¨ÄËÙÅ¡±’ù•∏∏°…ïù•Õ—…‰πΩ›π±ΩÖëï»§(%•òÄÖΩ¨ÅÏ($%–πÖ—Ö∞†âΩπÖ∏ÉB˚B«F?BﬂB√BÙÉFBÎB√FB„BÀB√FF0ÉBˇB˚BÔB˜F/B‰Å…ïç•¡îÅâ’πë±îÉFB◊FB◊B‹ÅΩ›π±ΩÖëï»à§(%Ù(%¡ÖÂ±ΩÖê∞Åô•±ïπÖµî∞Åï…»ÄËÙÅëΩ›π±ΩÖëï»πΩ›π±ΩÖê°çΩπ—ï·–π	Öç≠ù…Ω’πê†§∞Å…ïò∞Äƒ¿»–®ƒ¿»–§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%•òÄÖÕ—…•πùÃπ!ÖÕM’ôô•‡°ô•±ïπÖµî∞ÄàπçΩπÖ∏µ…ïç•¡îπ—ùËà§ÅÏ($%–π……Ω…ò†ãB„BÛF<Åâ’πë±îÄÙÄïƒà∞Åô•±ïπÖµî§(%Ù(%ùË∞Åï…»ÄËÙÅùÈ•¿π9ï›IïÖëï»°âÂ—ïÃπ9ï›IïÖëï»°¡ÖÂ±ΩÖê§§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%ëïôï»ÅùËπ±ΩÕî†§(%—»ÄËÙÅ—Ö»π9ï›IïÖëï»°ùË§(%ùΩ–ÄËÙÅµÖ¡mÕ—…•πùuÕ—…•πùÌÙ(%ôΩ»ÅÏ($%°ïÖëï»∞Åï…»ÄËÙÅ—»π9ï·–†§($%•òÅï…»ÄÙÙÅ•ºπ=ÅÏ($$%â…ïÖ¨($%Ù($%•òÅï…»ÄÑÙÅπ•∞ÅÏ($$%–πÖ—Ö∞°ï…»§($%Ù($%âΩë‰∞Å|ÄËÙÅ•ºπIïÖë±∞°—»§($%ùΩ—m°ïÖëï»π9ÖµïtÄÙÅÕ—…•πú°âΩë‰§(%Ù(%ôΩ»ÅπÖµî∞ÅâΩë‰ÄËÙÅ…ÖπùîÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$âçΩπÖπ}ï·¡Ω…–π—ùËàËÄâï·¡Ω…–à∞ÄâçΩπÖπ}ÕΩ’…çïÃπ—ùËàËÄâÕΩ’…çïÃà∞ÄâçΩπÖπô•±îπ¡‰àËÄâ…ïç•¡îà∞(%ÙÅÏ($%•òÅùΩ—mπÖµïtÄÑÙÅâΩë‰ÅÏ($$%–π……Ω…ò†àïÃËÉBˇB˚BÔFFB◊B˜B¯Äïƒ∞ÉB˚B€B„B”B√BÔB˚FF0Äïƒà∞ÅπÖµî∞ÅùΩ—mπÖµït∞ÅâΩë‰§($%Ù(%Ù)Ù()ô’πåÅQïÕ—ΩπÖπIïÖëÕ1•çïπÕïπëIï≈’•…ïµïπ—Õ…ΩµIïç•¡î°–Ä©—ïÕ—•πúπP§ÅÏ(%çΩπÕ–Å…ïŸ•Õ•Ω∏ÄÙÄâå·ê·êÿÿ‹‡‘Ÿåƒ‡…ê‘ÿ≈Ñà(%ô•±ïÕUI0ÄËÙÄâ°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩâΩΩÕ–ºƒ∏‰¿∏¿Ω|Ω|Ω…ïŸ•Õ•ΩπÃºàÄ¨Å…ïŸ•Õ•Ω∏Ä¨ÄàΩô•±ïÃà(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩâΩΩÕ–ºƒ∏‰¿∏¿Ω|Ω|Ω…ïŸ•Õ•ΩπÃàËÅÅÏâ…ïŸ•Õ•ΩπÃàÈl($$%Ïâ…ïŸ•Õ•Ω∏àËâÄÄ¨Å…ïŸ•Õ•Ω∏Ä¨ÅÄà∞â—•µîàËà»¿»ÿ¥¿ƒ¥¿≈Pƒ¿Ë¿¿Ë¿¡hâıuıÄ∞($%ô•±ïÕUI0ËÅÅÏâô•±ïÃàÈÏâçΩπÖπ}ï·¡Ω…–π—ùËàÈÌÙ∞âçΩπÖπô•±îπ¡‰àÈÌıııÄ∞($%ô•±ïÕUI0Ä¨ÄàΩçΩπÖπô•±îπ¡‰àËÅÄ($$%ç±ÖÕÃÅ	ΩΩÕ—ΩπÖ∏°ΩπÖπ•±î§Ë($$$ÄÄÄÅ±•çïπÕîÄÙÄâ	M0¥ƒ∏¿à($$$ÄÄÄÅ…ï≈’•…ïÃÄÙÄ†âÈ±•àΩl¯Ùƒ∏»∏ƒƒÄ…tà∞§($$$ÄÄÄÅëïòÅ…ï≈’•…ïµïπ—Ã°Õï±ò§Ë($$$ÄÄÄÄÄÄÄÅ•òÅÕï±òπΩ¡—•ΩπÃπ›•—°}âÈ•¿»Ë($$$ÄÄÄÄÄÄÄÄÄÄÄÅÕï±òπ…ï≈’•…ïÃ†ââÈ•¿»ºƒ∏¿∏‡à§($%Ä∞($$â°——¡ÃËºΩçΩπÖ∏π—ïÕ–Ωÿ»ΩçΩπÖπÃΩÕïÖ…ç†˝ƒıÈ±•àî…î…àËÅÅÏâ…ïÕ’±—ÃàÈlâÈ±•àºƒ∏»∏ƒÃà∞âÈ±•àºƒ∏Ã∏ƒà∞âΩ—°ï»º‰∏¿âuıÄ∞(%ıÙ(%¡±’ù•∏ÄËÙÅ¡±’ù•π]•—†°–∞ÄâçΩπÖ∏à∞Åò§(%…ïò∞Å|ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄââΩΩÕ–ºƒ∏‰¿∏¿à§(%µï—Ñ∞Åï…»ÄËÙÅ¡±’ù•∏πï—ç°5ï—ÖëÖ—Ñ°çΩπ—ï·–π	Öç≠ù…Ω’πê†§∞Å…ïò§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%•òÅµï—Ñπ1•çïπÕïMA`ÄÑÙÄâ	M0¥ƒ∏¿àÅÏ($%–π……Ω…ò†ãBÔB„FB◊B˜BﬂB„F<ÄÙÄïƒ∞ÉB˚B€B„B”B√BÔB√FF0Å	M0¥ƒ∏¿ÉB„B‹ÅçΩπÖπô•±îπ¡‰à∞Åµï—Ñπ1•çïπÕïMA`§(%Ù(%…ïÕΩ±Ÿï»∞ÅΩ¨ÄËÙÅ¡±’ù•∏∏°…ïù•Õ—…‰πï¡ïπëïπçÂIïÕΩ±Ÿï»§(%•òÄÖΩ¨ÅÏ($%–πÖ—Ö∞†âΩπÖ∏ÉB˜B‘ÉFB◊B√BÔB„BﬂFB◊FÅï¡ïπëïπçÂIïÕΩ±Ÿï»à§(%Ù(%…ï≈’•…ïµïπ—Ã∞Åï…»ÄËÙÅ…ïÕΩ±Ÿï»πIï≈’•…ïµïπ—Ã°çΩπ—ï·–π	Öç≠ù…Ω’πê†§∞Å…ïò§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%•òÅ±ï∏°…ï≈’•…ïµïπ—Ã§ÄÑÙÄ»ÅÒÅ…ï≈’•…ïµïπ—Õl¡tπ9ÖµîÄÑÙÄââÈ•¿»àÅÒÅ…ï≈’•…ïµïπ—Õl≈tπ9ÖµîÄÑÙÄâÈ±•ààÅÏ($%–πÖ—Ö±ò†ãBﬂB√BÀB„FB„BÛB˚FFB‡ÉFB◊FB◊BˇFB¿ËÄî≠ÿà∞Å…ï≈’•…ïµïπ—Ã§(%Ù(%Ÿï…Õ•ΩπÃ∞Åï…»ÄËÙÅ…ïÕΩ±Ÿï»πYï…Õ•ΩπÃ°çΩπ—ï·–π	Öç≠ù…Ω’πê†§∞ÄâÈ±•àà§(%•òÅï…»ÄÑÙÅπ•∞ÅÏ($%–πÖ—Ö∞°ï…»§(%Ù(%•òÅÕ—…•πùÃπ)Ω•∏°Ÿï…Õ•ΩπÃ∞Äà∞à§ÄÑÙÄàƒ∏»∏ƒÃ∞ƒ∏Ã∏ƒàÅÏ($%–π……Ω…ò†ãBÀB◊FFB„B‡ÅÈ±•àÄÙÄïÿà∞ÅŸï…Õ•ΩπÃ§(%Ù)Ù((ººÅQïÕ—ΩπÖπIï©ïç—ÕUÕï…°Öππï∞ÉäPÉBﬂB√BˇB„FF0ÉFÅ’Õï»Ωç°Öππï∞ÉB˚FBÀB◊FBœB√B◊FFF<ÉF(ººÉB˚B«F+F?FB˜B◊B˜B„B◊B∞ÉFFB¯ÉB„BÛB◊B˜B˜B¯ÉBÔB„F#B˜B◊B‘∏ÉBFB˚FFB¯É
ØB˜B◊BÀB◊FB˜F/B‰ÉFB˚FBÛB√F
ÏÉBﬂB√FFB√BÀB„BÔB¯ÉB«F,(ººÉBœB√B”B√FF0∏)ô’πåÅQïÕ—ΩπÖπIï©ïç—ÕUÕï…°Öππï∞°–Ä©—ïÕ—•πúπP§ÅÏ(%¡±’ù•∏ÄËÙÅ¡±’ù•π]•—†°–∞ÄâçΩπÖ∏à∞ÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÌıÙ§(%|∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞ÄâÈ±•àºƒ∏Ã∏≈’Õï»ΩÕ—Öâ±îà§(%•òÅï…»ÄÙÙÅπ•∞ÅÏ($%–πÖ—Ö∞†ãBﬂB√BˇB„FF0ÉFÉBÎB√B˜B√BÔB˚BÉBˇFB„B˜F?FB¿à§(%Ù(%•òÄÖÕ—…•πùÃπΩπ—Ö•πÃ°ï…»π……Ω»†§∞Äâ’Õï»Ωç°Öππï∞à§ÅÏ($%–π……Ω…ò†ãB˚F#B„B«BÎB¿ÉB˜B‘ÉB˚B«F+F?FB˜F?B◊F∞ÉFFB¯ÉBÔB„F#B˜B◊B‘ËÄïÿà∞Åï…»§(%Ù)Ù((ººÅQïÕ—Qï……ÖôΩ…µ5ï—ÖëÖ—ÑÉäPÉB”B„FFFB„B«FFB„B»ÉB‡ÉB◊BœB¯ÅÕ°Ñ»‘ÿÉB«B◊FFFFF<ÉBˇB˚B–ÉBÎB˚B˜BÎFB◊FB˜FF8(ººÉBˇBÔB√FFB˚FBÛFËÉFÉBˇBÔB√FFB˚FBÉFB√BﬂB˜F/B‘ÉB«B√BÁFF,∞ÉB‡ÉFFBÛBÛB¿ÉB˚B”B˜B˚B‰ÉB˜B„FB◊BœB¯ÉB˜B‘ÉBœB˚BÀB˚FB„FÉB¯ÉB”FFBœB˚B‰∏)ô’πåÅQïÕ—Qï……ÖôΩ…µ5ï—ÖëÖ—Ñ°–Ä©—ïÕ—•πúπP§ÅÏ(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩ—ï……ÖôΩ…¥π—ïÕ–ΩÿƒΩ¡…ΩŸ•ëï…ÃΩ°ÖÕ°•çΩ…¿ΩÖ›Ãº‘∏Ãƒ∏¿ΩëΩ›π±ΩÖêΩ±•π’‡ΩÖµêÿ–àËÅÄ($$%ÏâΩÃàËâ±•π’‡à∞âÖ…ç†àËâÖµêÿ–à∞âô•±ïπÖµîàËâ—ï……ÖôΩ…¥µ¡…ΩŸ•ëï»µÖ›Õ|‘∏Ãƒ∏¡}±•π’·}Öµêÿ–πÈ•¿à∞($$$ÄâëΩ›π±ΩÖë}’…∞àËâ°——¡ÃËºΩ…ï±ïÖÕïÃπ—ïÕ–ΩÖ›Õ|‘∏Ãƒ∏¡}±•π’·}Öµêÿ–πÈ•¿à∞($$$ÄâÕ°ÖÕ’¥àËâëïÖëâïïòâıÄ∞($$â°——¡ÃËºΩ—ï……ÖôΩ…¥π—ïÕ–ΩÿƒΩ¡…ΩŸ•ëï…ÃΩ°ÖÕ°•çΩ…¿ΩÖ›Ãº‘∏Ãƒ∏¿àËÅÄ($$%ÏâŸï…Õ•Ω∏àËà‘∏Ãƒ∏¿à∞â¡’â±•Õ°ïë}Ö–àËà»¿»Ã¥ƒƒ¥»¡Pƒ»Ë¿¿Ë¿¡hâıÄ∞(%ıÙ((%µï—ÑÄËÙÅµï—ÖΩ»°–∞Äâ—ï……ÖôΩ…¥à∞Äâ°ÖÕ°•çΩ…¿ΩÖ›Õ ‘∏Ãƒ∏¿à∞Åò§(%•òÅµï—Ñπ°ïç≠Õ’µ±ùºÄÑÙÄâÕ°Ñ»‘ÿàÅÒÅµï—Ñπ°ïç≠Õ’¥ÄÑÙÄâëïÖëâïïòàÅÏ($%–π……Ω…ò†ãBÎB˚B˜FFB˚BÔF3B˜B√F<ÉFFBÛBÛB¿ÄÙÄïÃºïƒà∞Åµï—Ñπ°ïç≠Õ’µ±ùº∞Åµï—Ñπ°ïç≠Õ’¥§(%Ù(%•òÅµï—Ñπ…—•ôÖç—•±ïπÖµîÄÑÙÄâ—ï……ÖôΩ…¥µ¡…ΩŸ•ëï»µÖ›Õ|‘∏Ãƒ∏¡}±•π’·}Öµêÿ–πÈ•¿àÅÏ($%–π……Ω…ò†ãB„BÛF<ÉFB√BÁBÔB¿ÄÙÄïƒà∞Åµï—Ñπ…—•ôÖç—•±ïπÖµî§(%Ù(%•òÅµï—ÑπA’â±•Õ°ïë–ÄÙÙÅπ•∞ÅÒÅµï—ÑπA’â±•Õ°ïë–πΩ…µÖ–†à»¿¿ÿ¥¿ƒ¥¿»à§ÄÑÙÄà»¿»Ã¥ƒƒ¥»¿àÅÏ($%–π……Ω…ò†ãB”B√FB¿ÉBˇFB«BÔB„BÎB√FB„B‡ÄÙÄïÿà∞Åµï—ÑπA’â±•Õ°ïë–§(%Ù)Ù((ººÅQïÕ—Qï……ÖôΩ…µA±Ö—ôΩ…µ%ππ—…‰ÉäPÉBˇBÔB√FFB˚FBÛFÉBÛB˚B€B˜B¯ÉFBÎB√BﬂB√FF0ÉB»ÉBﬂB√BˇB„FB‡∞ÉB‡ÉFB˚BœB”B¿(ººÉFBÎB√FB„BÀB√B◊FFF<ÉB„BÛB◊B˜B˜B¯ÉB◊FDÉB”B„FFFB„B«FFB„B»∏)ô’πåÅQïÕ—Qï……ÖôΩ…µA±Ö—ôΩ…µ%ππ—…‰°–Ä©—ïÕ—•πúπP§ÅÏ(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩ—ï……ÖôΩ…¥π—ïÕ–ΩÿƒΩ¡…ΩŸ•ëï…ÃΩ°ÖÕ°•çΩ…¿ΩÖ›Ãº‘∏Ãƒ∏¿ΩëΩ›π±ΩÖêΩëÖ…›•∏ΩÖ…¥ÿ–àËÅÄ($$%ÏâëΩ›π±ΩÖë}’…∞àËâ°——¡ÃËºΩ…ï±ïÖÕïÃπ—ïÕ–ΩÖ›Õ}ëÖ…›•π}Ö…¥ÿ–πÈ•¿à∞âÕ°ÖÕ’¥àËâçÖôîâıÄ∞(%ıÙ(%µï—ÑÄËÙÅµï—ÖΩ»°–∞Äâ—ï……ÖôΩ…¥à∞Äâ°ÖÕ°•çΩ…¿ΩÖ›Õ ‘∏Ãƒ∏¿ÈëÖ…›•π}Ö…¥ÿ–à∞Åò§(%•òÄÖÕ—…•πùÃπΩπ—Ö•πÃ°µï—Ñπ…—•ôÖç—UI0∞ÄâëÖ…›•π}Ö…¥ÿ–à§ÅÏ($%–π……Ω…ò†ãFBÎB√FB„BÀB√B◊FFF<ÉB˜B‘ÉFB¿ÉBˇBÔB√FFB˚FBÛB¿ËÄïÃà∞Åµï—Ñπ…—•ôÖç—UI0§(%Ù)Ù((ººÅQïÕ—1’ÖIΩç≠Õ5ï—ÖëÖ—ÑÉäPÉBÔB„FB◊B˜BﬂB„F<ÉB”B˚FFB√FGFFF<ÉB„B‹Å…Ωç≠Õ¡ïåÉFB√BﬂB«B˚FB˚BÉB˚B”B˜B˚BœB¯ÉBˇB˚BÔF<Ë(ººÅ…Ωç≠Õ¡ïåÉäPÉF7FB¯Å1’Ñ∑BÎB˚B–∞ÉB‡ÉB„FBˇB˚BÔB˜F?FF0ÉB◊BœB¯ÉFB√B”B‡ÉFFFB˚FBÎB‡ÉBÔB„FB◊B˜BﬂB„B‡ÉB˜B◊BÔF3BﬂF<∏)ô’πåÅQïÕ—1’ÖIΩç≠Õ5ï—ÖëÖ—Ñ°–Ä©—ïÕ—•πúπP§ÅÏ(%òÄËÙÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÏ($$â°——¡ÃËºΩ±’Ö…Ωç≠Ãπ—ïÕ–Ω±’ÖÕΩç≠ï–¥Ã∏ƒ∏¿¥ƒπ…Ωç≠Õ¡ïåàËÅÄ($$%¡Öç≠ÖùîÄÙÄâ±’ÖÕΩç≠ï–à($$%Ÿï…Õ•Ω∏ÄÙÄàÃ∏ƒ∏¿¥ƒà($$%ëïÕç…•¡—•Ω∏ÄÙÅÏ($$$ÄÄÅÕ’µµÖ…‰ÄÙÄâ9ï—›Ω…¨ÅÕ’¡¡Ω…–ÅôΩ»Å1’Ñà∞($$$ÄÄÅ±•çïπÕîÄÙÄâ5%Pà($$%ıÄ∞(%ıÙ((%µï—ÑÄËÙÅµï—ÖΩ»°–∞Äâ±’Ö…Ωç≠Ãà∞Äâ±’ÖÕΩç≠ï— Ã∏ƒ∏¿¥ƒà∞Åò§(%•òÅµï—Ñπ1•çïπÕïMA`ÄÑÙÄâ5%PàÅÏ($%–π……Ω…ò†ãBÔB„FB◊B˜BﬂB„F<ÄÙÄïƒà∞Åµï—Ñπ1•çïπÕïMA`§(%Ù(%•òÅµï—Ñπ…—•ôÖç—•±ïπÖµîÄÑÙÄâ±’ÖÕΩç≠ï–¥Ã∏ƒ∏¿¥ƒπÕ…åπ…Ωç¨àÅÏ($%–π……Ω…ò†ãB„BÛF<ÉFB√BÁBÔB¿ÄÙÄïƒà∞Åµï—Ñπ…—•ôÖç—•±ïπÖµî§(%Ù($ººÉBSB√FF,ÉBˇFB«BÔB„BÎB√FB„B‡Å±’Ö…Ωç≠ÃÉB˜B‘ÉB˚FB”B√FGFËÉBÎB√FB√B˜FB„BÙÉB«FB”B◊FÉBˇFB˚BˇFF'B◊BÙÉFÉBˇB˚BÛB◊FBÎB˚B‰∏($ººÉBKF/B”FBÛB√B˜B˜B√F<ÉB”B√FB¿ÉBﬂB”B◊FF0ÉB˚BﬂB˜B√FB√BÔB¿ÉB«F,ÉBÛB˚BÔFB¿ÉBˇFB˚BÁB”B◊B˜B˜F/B‰ÉBÎB√FB√B˜FB„BÙ∏(%•òÅµï—ÑπA’â±•Õ°ïë–ÄÑÙÅπ•∞ÅÏ($%–π……Ω…ò†ãB”B√FB¿ÉBˇFB«BÔB„BÎB√FB„B‡ÄÙÄïÿ∞ÉB¿Å±’Ö…Ωç≠ÃÉB◊FDÉB˜B‘ÉFB˚B˚B«F'B√B◊Fà∞Åµï—ÑπA’â±•Õ°ïë–§(%Ù)Ù((ººÅQïÕ—1’ÖIΩç≠ÕIï≈’•…ïÕIïŸ•Õ•Ω∏ÉäPÉBÀB◊FFB„F<ÉB«B◊B‹ÉFB◊BÀB„BﬂB„B‡ÉB˚FBÀB◊FBœB√B◊FFF<ËÉFB◊BÀB„BﬂB„F<(ººÉBÀFB˚B”B„FÉB»ÉB„BÛF<ÉFB√BÁBÔB¿Å…Ωç¨üB¿∞ÉB‡ÉB«B◊B‹ÉB˜B◊FDÉFBÎB√FB„BÀB√FF0ÉB˜B◊FB◊BœB¯∏)ô’πåÅQïÕ—1’ÖIΩç≠ÕIï≈’•…ïÕIïŸ•Õ•Ω∏°–Ä©—ïÕ—•πúπP§ÅÏ(%¡±’ù•∏ÄËÙÅ¡±’ù•π]•—†°–∞Äâ±’Ö…Ωç≠Ãà∞ÄôôÖ≠ïIïù•Õ—…ÂÌ…ïÕ¡ΩπÕïÃËÅµÖ¡mÕ—…•πùuÕ—…•πùÌıÙ§(%|∞Åï…»ÄËÙÅ…ïù•Õ—…‰πAÖ…Õïπ—…‰°¡±’ù•∏∞Äâ±’ÖÕΩç≠ï— Ã∏ƒ∏¿à§(%•òÅï…»ÄÙÙÅπ•∞ÅÏ($%–πÖ—Ö∞†ãBÀB◊FFB„F<ÉB«B◊B‹ÉFB◊BÀB„BﬂB„B‡ÉBˇFB„B˜F?FB¿à§(%Ù(%•òÄÖÕ—…•πùÃπΩπ—Ö•πÃ°ï…»π……Ω»†§∞ÄãBÉBWBKBcB_BcBWBdà§ÅÏ($%–π……Ω…ò†ãB˚F#B„B«BÎB¿ÉB˜B‘ÉB˚B«F+F?FB˜F?B◊F∞ÉFB◊BœB¯ÉB˜B‘ÉFBÀB√FB√B◊FËÄïÿà∞Åï…»§(%Ù)Ù(