// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kcidb

// Kernel CI report data. To be submitted to/queried from the common report database.
//
// Objects in the data are identified and linked together using "id" and "*_id" string properties.
// Each value of these properties must start with a non-empty string identifying the CI system which
// submitted the object, followed by a colon ':' character. The rest of the string is generated by
// the origin CI system, and must identify that object uniquely among all objects of the same type,
// coming from that CI system.
//
// Any of the immediate properties (except "version") can be missing or be an empty list with each
// submission/query, but only complete data stored in the database should be considered valid.
//
// E.g. a test run referring to a non-existent build is allowed into/from the database,
// but would only appear in reports once both the build and its revision are present.
//
// No special meaning apart from "data is missing" is attached to any immediate or deeper properties being omitted,
// when they're not required, and no default values should be assumed for them.
// At the same time, no properties can be null.
//
// Extra free-form data can be stored under "misc" fields associated with various objects throughout the schema,
// if necessary. That data could later be used as the basis for defining new properties to house it.
type Kcidb struct {
	Revisions []*Revision `json:"revisions,omitempty"`
	Builds    []*Build    `json:"builds,omitempty"`
	Tests     []*Test     `json:"tests,omitempty"`
	Version   *Version    `json:"version"`
}

// A build of a revision.
type Build struct {
	// Target architecture of the build.
	Architecture string `json:"architecture,omitempty"`

	// Full shell command line used to make the build, including environment variables.
	Command string `json:"command,omitempty"`

	// Name and version of the compiler used to make the build.
	Compiler string `json:"compiler,omitempty"`

	// A name describing the build configuration options.
	ConfigName string `json:"config_name,omitempty"`

	// The URL of the build configuration file.
	ConfigURL string `json:"config_url,omitempty"`

	// Human-readable description of the build.
	Description string `json:"description,omitempty"`

	// The number of seconds it took to complete the build.
	Duration float64 `json:"duration,omitempty"`

	// Build ID.
	// Must start with a non-empty string identifying the CI system which submitted the build,
	// followed by a colon ':' character. The rest of the string is generated by the origin CI system,
	// and must identify the build uniquely among all builds, coming from that CI system.
	ID string `json:"id"`

	// A list of build input files. E.g. configuration.
	InputFiles []*Resource `json:"input_files,omitempty"`

	// The URL of the build log file.
	LogURL string `json:"log_url,omitempty"`

	// Miscellaneous extra data about the build.
	Misc *BuildMisc `json:"misc,omitempty"`

	// The name of the CI system which submitted the build.
	Origin string `json:"origin"`

	// A list of build output files: images, packages, etc.
	OutputFiles []*Resource `json:"output_files,omitempty"`

	// ID of the built revision. The revision must be valid for the build to be considered valid.
	RevisionID string `json:"revision_id"`

	// The time the build was started.
	StartTime string `json:"start_time,omitempty"`

	// True if the build is valid, i.e. if it could be completed.
	Valid bool `json:"valid"`
}

// Miscellaneous extra data about the build.
type BuildMisc struct {
	ReportedBy string `json:"reported_by,omitempty"`
}

// The environment the test ran in. E.g. a host, a set of hosts, or a lab;
// amount of memory/storage/CPUs, for each host; process environment variables, etc.
type Environment struct {
	// Human-readable description of the environment.
	Description string `json:"description,omitempty"`

	// Miscellaneous extra data about the environment.
	Misc *EnvironmentMisc `json:"misc,omitempty"`
}

// Miscellaneous extra data about the environment.
type EnvironmentMisc struct {
}

// A revision of the tested code.
//
// Represents a way the tested source code could be obtained. E.g. checking out a particular commit from a git repo,
// and applying a set of patches on top.
type Revision struct {
	// List of e-mail addresses of contacts concerned with this revision, such as authors, reviewers, and mail lists.
	Contacts []string `json:"contacts,omitempty"`

	// Human-readable description of the revision. E.g. a release version, or the subject of a patchset message.
	Description string `json:"description,omitempty"`

	// The time the revision was discovered by the CI system. E.g. the time the CI system found a patch message,
	// or noticed a new commit or a new tag in a git repo.
	DiscoveryTime string `json:"discovery_time,omitempty"`

	// The full commit hash of the revision's base code.
	GitCommitHash string `json:"git_commit_hash,omitempty"`

	// A human-readable name of the commit containing the base code of the revision,
	// as would be output by "git describe", at the discovery time.
	GitCommitName string `json:"git_commit_name,omitempty"`

	// The Git repository branch in which the commit with the revision's base code was discovered.
	GitRepositoryBranch string `json:"git_repository_branch,omitempty"`

	// The URL of the Git repository which contains the base code of the revision.
	// The shortest possible https:// URL, or, if that's not available, the shortest possible git:// URL.
	GitRepositoryURL string `json:"git_repository_url,omitempty"`

	// Revision ID.
	//
	// Must contain the full commit hash of the revision's base code in the Git repository.
	//
	// If the revision had patches applied to the base code, the commit hash should be followed by the '+'
	// character and a sha256 hash over newline-terminated sha256 hashes of each applied patch, in order.
	// E.g. generated with this shell command: "sha256sum *.patch | cut -c-64 | sha256sum | cut -c-64".
	ID string `json:"id"`

	// The URL of the log file of the attempt to construct this revision from its parts. E.g. 'git am' output.
	LogURL string `json:"log_url,omitempty"`

	// The value of the Message-ID header of the e-mail message introducing this code revision,
	// if any. E.g. a message with the revision's patchset, or a release announcement sent to a maillist.
	MessageID string `json:"message_id,omitempty"`

	// Miscellaneous extra data about the revision.
	Misc *RevisionMisc `json:"misc,omitempty"`

	// The name of the CI system which submitted the revision.
	Origin string `json:"origin"`

	// List of mboxes containing patches applied to the base code of the revision, in order of application.
	PatchMboxes []*Resource `json:"patch_mboxes,omitempty"`

	// The time the revision was made public. E.g. the timestamp on a patch message, a commit, or a tag.
	PublishingTime string `json:"publishing_time,omitempty"`

	// The widely-recognized name of the sub-tree (fork) of the main code tree that the revision belongs to.
	TreeName string `json:"tree_name,omitempty"`

	// True if the revision is valid, i.e. if its parts could be combined.
	// False if not, e.g. if its patches failed to apply.
	Valid bool `json:"valid"`
}

// Miscellaneous extra data about the revision.
type RevisionMisc struct {
}

// A test run against a build.
//
// Could represent a result of execution of a test suite program, a result of one of the tests done by the test
// suite program, as well as a summary of a collection of test suite results.
//
// Each test run should normally have a dot-separated test "path" specified in the "path" property,
// which could identify a specific test within a test suite (e.g. "LTPlite.sem01"), a whole test suite
// (e.g. "LTPlite"), or the summary of all tests for a build ( - the empty string).
type Test struct {
	// ID of the tested build. The build must be valid for the test run to be considered valid.
	BuildID string `json:"build_id"`

	// Human-readable description of the test run.
	Description string `json:"description,omitempty"`

	// The number of seconds it took to run the test.
	Duration float64 `json:"duration,omitempty"`

	// The environment the test ran in. E.g. a host, a set of hosts, or a lab; amount of memory/storage/CPUs,
	// for each host; process environment variables, etc.
	Environment *Environment `json:"environment,omitempty"`

	// ID of the test run.
	// Must start with a non-empty string identifying the CI system which submitted the test run,
	// followed by a colon ':' character. The rest of the string is generated by the origin CI system,
	// and must identify the test run uniquely among all test runs, coming from that CI system.
	ID string `json:"id"`

	// Miscellaneous extra data about the test run.
	Misc *TestMisc `json:"misc,omitempty"`

	// The name of the CI system which submitted the test run.
	Origin string `json:"origin"`

	// A list of test outputs: logs, dumps, etc.
	OutputFiles []*Resource `json:"output_files,omitempty"`

	// Dot-separated path to the node in the test classification tree the executed test belongs to.
	// E.g. "ltp.sem01". The empty string signifies the root of the tree, i.e. all tests for the build,
	// executed by the origin CI system.
	Path string `json:"path,omitempty"`

	// The time the test run was started.
	StartTime string `json:"start_time,omitempty"`

	// The test status string, one of the following. "ERROR" - the test is faulty, the status of the tested
	// code is unknown.
	// "FAIL" - the test has failed, the tested code is faulty.
	// "PASS" - the test has passed, the tested code is correct.
	// "DONE" - the test has finished successfully, the status of the tested code is unknown.
	// "SKIP" - the test wasn't executed, the status of the tested code is unknown.
	//
	// The status names above are listed in priority order (highest to lowest), which could be used for producing
	// a summary status for a collection of test runs, e.g. for all testing done on a build, based on results of
	// executed test suites. The summary status would be the highest priority status across all test runs
	// in a collection.
	Status string `json:"status,omitempty"`

	// True if the test status should be ignored.
	// Could be used for reporting test results without affecting the overall test status and alerting
	// the contacts concerned with the tested code revision. For example, for collecting test reliability
	// statistics when the test is first introduced, or is being fixed.
	Waived bool `json:"waived,omitempty"`
}

// Miscellaneous extra data about the test.
type TestMisc struct {
	ReportedBy      string `json:"reported_by,omitempty"`
	UserSpaceArch   string `json:"user_space_arch,omitempty"`
	CauseRevisionID string `json:"cause_revision_id,omitempty"`
}

// A named remote resource.
type Resource struct {
	// Resource name. Must be usable as a local file name for the downloaded resource. Cannot be empty.
	// Should not include directories.
	Name string `json:"name"`

	// Resource URL. Must point to the resource file directly, so it could be downloaded automatically.
	URL string `json:"url"`
}

type Version struct {
	// Major number of the schema version.
	//
	// Increases represent backward-incompatible changes. E.g. deleting or renaming a property,
	// changing a property type, restricting values, making a property required, or adding a new required property.
	Major int `json:"major"`

	// Minor number of the schema version.
	//
	// Increases represent backward-compatible changes. E.g. relaxing value restrictions,
	// making a property optional, or adding a new optional property.
	Minor int `json:"minor"`
}
