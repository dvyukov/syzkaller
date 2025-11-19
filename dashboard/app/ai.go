// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/app/aidb"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/vcs"
	db "google.golang.org/appengine/v2/datastore"
)

const AIAccessLevel = AccessUser

type uiAIJobsPage struct {
	Header *uiHeader
	Jobs   []*uiAIJob
}

type uiAIJobPage struct {
	Header     *uiHeader
	Jobs       []*uiAIJob
	Results    []*uiAIResult
	Trajectory []*uiAITrajectorySpan
}

type uiAIJob struct {
	ID              string
	Link            string
	Workflow        string
	Description     string
	DescriptionLink string

	Created          time.Time
	Started          time.Time
	Finished         time.Time
	LLMModel         string
	CodeRevision     string
	CodeRevisionLink string
	Error            string
}

type uiAIResult struct {
	Name  string
	Value any
}

type uiAITrajectorySpan struct {
	Timestamp   time.Time
	Seq         int64
	Nesting     int64
	Type        string
	Name        string
	Duration    time.Duration
	Error       string
	Args        string
	Results     string
	Instruction string
	Prompt      string
	Reply       string
	Thoughts    string
}

func handleAIJobsPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if err := checkAccessLevel(ctx, r, AIAccessLevel); err != nil {
		return err
	}
	hdr, err := commonHeader(ctx, r, w, "")
	if err != nil {
		return err
	}
	jobs, err := aidb.LoadNamespaceJobs(ctx, hdr.Namespace)
	if err != nil {
		return err
	}
	var uiJobs []*uiAIJob
	for _, job := range jobs {
		uiJobs = append(uiJobs, makeUIAIJob(job))
	}
	page := &uiAIJobsPage{
		Header: hdr,
		Jobs:   uiJobs,
	}
	return serveTemplate(w, "ai_jobs.html", page)
}

func handleAIJobPage(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if err := checkAccessLevel(ctx, r, AIAccessLevel); err != nil {
		return err
	}
	job, err := aidb.LoadJob(ctx, r.FormValue("id"))
	if err != nil {
		return err
	}
	trajectory, err := aidb.LoadTrajectory(ctx, job.ID)
	if err != nil {
		return err
	}
	hdr, err := commonHeader(ctx, r, w, job.Namespace)
	if err != nil {
		return err
	}
	page := &uiAIJobPage{
		Header:     hdr,
		Jobs:       []*uiAIJob{makeUIAIJob(job)},
		Trajectory: makeUIAITrajectory(trajectory),
	}
	if m, ok := job.Results.Value.(map[string]any); ok && job.Results.Valid {
		for name, value := range m {
			page.Results = append(page.Results, &uiAIResult{
				Name:  name,
				Value: value,
			})
		}
	}
	slices.SortFunc(page.Results, func(a, b *uiAIResult) int {
		return strings.Compare(a.Name, b.Name)
	})
	return serveTemplate(w, "ai_job.html", page)
}

func makeUIAIJob(job *aidb.Job) *uiAIJob {
	return &uiAIJob{
		ID:               job.ID,
		Link:             fmt.Sprintf("/ai_job?id=%v", job.ID),
		Workflow:         job.Workflow,
		Description:      job.Description,
		DescriptionLink:  job.Link,
		Created:          job.Created,
		Started:          nullTime(job.Started),
		Finished:         nullTime(job.Finished),
		LLMModel:         job.LLMModel,
		CodeRevision:     job.CodeRevision,
		CodeRevisionLink: vcs.LogLink(vcs.SyzkallerRepo, job.CodeRevision),
		Error:            job.Error,
	}
}

func makeUIAITrajectory(trajetory []*aidb.TrajectorySpan) []*uiAITrajectorySpan {
	var res []*uiAITrajectorySpan
	for _, span := range trajetory {
		res = append(res, &uiAITrajectorySpan{
			Timestamp:   span.Timestamp,
			Seq:         span.Seq,
			Nesting:     span.Nesting,
			Type:        span.Type,
			Name:        span.Name,
			Duration:    nullDuration(span.Duration),
			Error:       nullString(span.Error),
			Args:        nullJSON(span.Args),
			Results:     nullJSON(span.Results),
			Instruction: nullString(span.Instruction),
			Prompt:      nullString(span.Prompt),
			Reply:       nullString(span.Reply),
			Thoughts:    nullString(span.Thoughts),
		})
	}
	return res
}

func nullTime(v spanner.NullTime) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return v.Time
}

func nullDuration(v spanner.NullInt64) time.Duration {
	if !v.Valid {
		return 0
	}
	return time.Duration(v.Int64)
}

func nullString(v spanner.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.StringVal
}

func nullJSON(v spanner.NullJSON) string {
	if !v.Valid {
		return ""
	}
	return fmt.Sprint(v.Value)
}

func apiAIJobPoll(ctx context.Context, req *dashapi.AIJobPollReq) (any, error) {
	if err := aidb.UpdateWorkflows(ctx, req.Workflows); err != nil {
		return nil, fmt.Errorf("UpdateWorkflows: %w", err)
	}
	job, err := aidb.StartJob(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("StartJob: %w", err)
	}
	if job == nil {
		if created, err := autoCreateAIJobs(ctx); err != nil || !created {
			return &dashapi.AIJobPollResp{}, err
		}
		job, err = aidb.StartJob(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("StartJob: %w", err)
		}
	}
	args := make(map[string]any)
	var textErr error
	assignText := func(anyID any, tag, name string) {
		id, err := anyID.(json.Number).Int64()
		if err != nil {
			textErr = err
		}
		data, _, err := getText(ctx, tag, id)
		if err != nil {
			textErr = err
		}
		args[name] = string(data)
	}
	if job.Args.Valid {
		for name, val := range job.Args.Value.(map[string]any) {
			switch name {
			case "ReproSyzID":
				assignText(val, textReproSyz, "ReproSyz")
			case "ReproCID":
				assignText(val, textReproC, "ReproC")
			case "CrashReportID":
				assignText(val, textCrashReport, "CrashReport")
			case "KernelConfigID":
				assignText(val, textKernelConfig, "KernelConfig")
			default:
				args[name] = val
			}
		}
		if textErr != nil {
			return nil, textErr
		}
	}
	return &dashapi.AIJobPollResp{
		ID:       job.ID,
		Type:     string(job.Type),
		Workflow: job.Workflow,
		Args:     args,
	}, nil
}

func apiAIJobDone(ctx context.Context, req *dashapi.AIJobDoneReq) (any, error) {
	job, err := aidb.LoadJob(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if job.Finished.Valid {
		return nil, fmt.Errorf("the job %v is already finished", req.ID)
	}
	job.Finished = spanner.NullTime{Time: timeNow(ctx), Valid: true}
	job.Error = req.Error[:min(len(req.Error), 4<<10)]
	if len(req.Results) != 0 {
		job.Results = spanner.NullJSON{Value: req.Results, Valid: true}
	}
	err = aidb.UpdateJob(ctx, job)
	return nil, err
}

func apiAITrajectoryLog(ctx context.Context, req *dashapi.AITrajectoryReq) (any, error) {
	err := aidb.StoreTrajectorySpan(ctx, req.JobID, req.Span)
	return nil, err
}

func aiBugWorkflows(ctx context.Context, bug *Bug) ([]string, error) {
	workflows, err := aidb.LoadWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	var applicable []string
	for _, flow := range workflows {
		if timeSince(ctx, flow.LastActive) > 25*time.Hour {
			continue
		}
		switch flow.Type {
		case aidb.WorkflowPatching:
			if bug.ReproLevel == dashapi.ReproLevelNone {
				continue
			}
		case aidb.WorkflowModeration:
		default:
			continue
		}
		applicable = append(applicable, flow.Name)
	}
	slices.Sort(applicable)
	return applicable, nil
}

func aiBugJobCreate(ctx context.Context, workflow string, bug *Bug) error {
	typ := aidb.WorkflowType(strings.Split(workflow, "-")[0])
	crash, crashKey, err := findCrashForBug(ctx, bug)
	if err != nil {
		return err
	}
	build, err := loadBuild(ctx, bug.Namespace, crash.BuildID)
	if err != nil {
		return err
	}
	tx := func(ctx context.Context) error {
		return addCrashReference(ctx, crashKey.IntID(), bug.key(ctx),
			CrashReference{CrashReferenceAIJob, "", timeNow(ctx)})
	}
	if err := runInTransaction(ctx, tx, &db.TransactionOptions{
		XG: true,
	}); err != nil {
		return fmt.Errorf("addCrashReference failed: %w", err)
	}
	return aidb.CreateJob(ctx, &aidb.Job{
		Type:        typ,
		Workflow:    workflow,
		Namespace:   bug.Namespace,
		BugID:       spanner.NullString{StringVal: bug.keyHash(ctx), Valid: true},
		Description: bug.displayTitle(),
		Link:        fmt.Sprintf("/bug?id=%v", bug.keyHash(ctx)),
		Args: spanner.NullJSON{Valid: true, Value: map[string]any{
			"ReproOpts":       string(crash.ReproOpts),
			"ReproSyzID":      crash.ReproSyz,
			"ReproCID":        crash.ReproC,
			"CrashReportID":   crash.Report,
			"KernelRepo":      build.KernelRepo,
			"KernelCommit":    build.KernelCommit,
			"KernelConfigID":  build.KernelConfig,
			"SyzkallerCommit": build.SyzkallerCommit,
		}},
	})
}

func autoCreateAIJobs(ctx context.Context) (bool, error) {
	for ns, cfg := range getConfig(ctx).Namespaces {
		if cfg.AI == nil {
			continue
		}
		var bugs []*Bug
		keys, err := db.NewQuery("Bug").
			Filter("Namespace=", ns).
			Filter("Status=", BugStatusOpen).
			Filter("AIJobCheck<", currentAIJobCheckSeq).
			Limit(100).
			GetAll(ctx, &bugs)
		if err != nil {
			return false, fmt.Errorf("failed to fetch bugs: %w", err)
		}
		if len(bugs) == 0 {
			continue
		}
		created := false
		var updateKeys []*db.Key
		for i, bug := range bugs {
			updateKeys = append(updateKeys, keys[i])
			created, err = autoCreateAIJob(ctx, bug, keys[i])
			if err != nil {
				return false, err
			}
			if created {
				break
			}
		}
		if err := updateBatch(ctx, updateKeys, func(_ *db.Key, bug *Bug) {
			bug.AIJobCheck = currentAIJobCheckSeq
		}); err != nil {
			return false, err
		}
		if created {
			break
		}
	}
	return false, nil
}

func autoCreateAIJob(ctx context.Context, bug *Bug, bugKey *db.Key) (bool, error) {
	workflows := workflowsForBug(bug)
	if len(workflows) == 0 {
		return false, nil
	}
	jobs, err := aidb.LoadBugJobs(ctx, bugKey.StringID())
	if err != nil {
		return false, err
	}
	for _, job := range jobs {
		if !job.Finished.Valid {
			delete(workflows, job.Workflow)
		}
		if job.Finished.Valid && job.Error == "" {
			delete(workflows, job.Workflow)
		}
		//!!! what to do with finished error jobs?
	}
	for workflow := range workflows {
		if err := aiBugJobCreate(ctx, workflow, bug); err != nil {
			return false, err
		}
	}
	return len(workflows) != 0, nil
}

const currentAIJobCheckSeq = 10

func workflowsForBug(bug *Bug) map[string]bool {
	workflows := make(map[string]bool)
	if strings.HasPrefix(bug.Title, "KCSAN: data-race") {
		workflows["moderation-baseline"] = true
	}
	return workflows
}
