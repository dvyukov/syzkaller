// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2"
)

const (
	Instance = "syzbot"
	Database = "ai"
)

func init() {
	// This forces unmarshalling of JSON integers into json.Number rather than float64.
	spanner.UseNumberWithJSONDecoderEncoder(true)
}

func LoadWorkflows(ctx context.Context) ([]*Workflow, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT * FROM Workflows`,
	})
	defer iter.Stop()
	var workflows []*Workflow
	err = spanner.SelectAll(iter, &workflows)
	return workflows, err
}

func UpdateWorkflows(ctx context.Context, active []dashapi.AIWorkflow) error {
	workflows, err := LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]*Workflow)
	for _, f := range workflows {
		m[f.Name] = f
	}
	nowDate := TimeNow(ctx).Truncate(24 * time.Hour)
	var mutations []*spanner.Mutation
	for _, f := range active {
		flow := &Workflow{
			Name:         f.Name,
			Type:         WorkflowType(f.Type),
			Experimental: f.Experimental,
			LastActive:   nowDate,
		}
		if have := m[flow.Name]; reflect.DeepEqual(have, flow) {
			continue
		}
		mut, err := spanner.InsertOrUpdateStruct("Workflows", flow)
		if err != nil {
			return err
		}
		mutations = append(mutations, mut)
	}
	if len(mutations) == 0 {
		return nil
	}
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.Apply(ctx, mutations)
	return err
}

func CreateJob(ctx context.Context, job *Job) error {
	job.ID = uuid.NewString()
	job.Created = TimeNow(ctx)
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.InsertStruct("Jobs", job)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func UpdateJob(ctx context.Context, job *Job) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	mut, err := spanner.UpdateStruct("Jobs", job)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func StartJob(ctx context.Context, req *dashapi.AIJobPollReq) (*Job, error) {
	var workflows []string
	for _, flow := range req.Workflows {
		workflows = append(workflows, flow.Name)
	}
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	var job *Job
	//!!! add attempts, restart jobs after X hours
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
		{
			iter := txn.Query(ctx, spanner.Statement{
				SQL: `SELECT * FROM Jobs WHERE Workflow IN UNNEST(@workflows)
						AND Started IS NULL
					ORDER BY Created ASC LIMIT 1`,
				Params: map[string]any{
					"workflows": workflows,
				},
			})
			defer iter.Stop()
			var jobs []*Job
			if err := spanner.SelectAll(iter, &jobs); err != nil || len(jobs) == 0 {
				return err
			}
			job = jobs[0]
		}
		job.Started = spanner.NullTime{
			Time:  TimeNow(ctx),
			Valid: true,
		}
		job.LLMModel = req.LLMModel
		job.CodeRevision = req.CodeRevision
		mut, err := spanner.InsertOrUpdateStruct("Jobs", job)
		if err != nil {
			return err
		}
		return txn.BufferWrite([]*spanner.Mutation{mut})
	})
	return job, err
}

func LoadNamespaceJobs(ctx context.Context, ns string) ([]*Job, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT * FROM Jobs WHERE Namespace = @ns ORDER BY Created DESC`,
		Params: map[string]any{
			"ns": ns,
		},
	})
	defer iter.Stop()
	var jobs []*Job
	err = spanner.SelectAll(iter, &jobs)
	return jobs, err
}

func LoadBugJobs(ctx context.Context, bugID string) ([]*Job, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT * FROM Jobs WHERE BugID = @bugID ORDER BY Created DESC`,
		Params: map[string]any{
			"bugID": bugID,
		},
	})
	defer iter.Stop()
	var jobs []*Job
	err = spanner.SelectAll(iter, &jobs)
	return jobs, err
}

func LoadJob(ctx context.Context, id string) (*Job, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT * FROM Jobs WHERE ID = @id`,
		Params: map[string]any{
			"id": id,
		},
	})
	defer iter.Stop()
	var jobs []*Job
	err = spanner.SelectAll(iter, &jobs)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("did not find job with id %q", id)
	}
	return jobs[0], nil
}

func StoreTrajectorySpan(ctx context.Context, jobID string, span *trajectory.Span) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	ent := TrajectorySpan{
		JobID:       jobID,
		Seq:         int64(span.Seq),
		Nesting:     int64(span.Nesting),
		Type:        string(span.Type),
		Name:        span.Name,
		Timestamp:   span.Timestamp,
		Finished:    span.Finished,
		Duration:    toDuration(span.Duration),
		Error:       toString(span.Error),
		Args:        toJSON(span.Args),
		Results:     toJSON(span.Results),
		Instruction: toString(span.Instruction),
		Prompt:      toString(span.Prompt),
		Reply:       toString(span.Reply),
		Thoughts:    toString(span.Thoughts),
	}
	mut, err := spanner.InsertOrUpdateStruct("TrajectorySpans", ent)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{mut})
	return err
}

func LoadTrajectory(ctx context.Context, jobID string) ([]*TrajectorySpan, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT * FROM TrajectorySpans WHERE JobID = @job_id ORDER BY Seq ASC`,
		Params: map[string]any{
			"job_id": jobID,
		},
	})
	defer iter.Stop()
	var items []*TrajectorySpan
	err = spanner.SelectAll(iter, &items)
	if err != nil {
		return nil, err
	}
	return items, nil
}

var TimeNow = func(ctx context.Context) time.Time {
	return time.Now()
}

func dbClient(ctx context.Context) (*spanner.Client, error) {
	path := fmt.Sprintf("projects/%v/instances/%v/databases/%v",
		appengine.AppID(ctx), Instance, Database)
	return spanner.NewClientWithConfig(ctx, path, spanner.ClientConfig{
		SessionPoolConfig: spanner.SessionPoolConfig{
			MinOpened: 1,
			MaxOpened: 1,
		},
	})
}

func toJSON(v map[string]any) spanner.NullJSON {
	if v == nil {
		return spanner.NullJSON{}
	}
	return spanner.NullJSON{Value: v, Valid: true}
}

func toDuration(v time.Duration) spanner.NullInt64 {
	if v == 0 {
		return spanner.NullInt64{}
	}
	return spanner.NullInt64{Int64: int64(v), Valid: true}
}

func toString(v string) spanner.NullString {
	if v == "" {
		return spanner.NullString{}
	}
	return spanner.NullString{StringVal: v, Valid: true}
}
