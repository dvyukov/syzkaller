CREATE TABLE Workflows (
	Name			STRING(1000) NOT NULL,
	Type			STRING(1000) NOT NULL,
	Experimental		BOOL NOT NULL,
	LastActive		TIMESTAMP NOT NULL,

	CONSTRAINT Workflows_TypeEnum CHECK (Type IN ('patching', 'moderation')),
) PRIMARY KEY (Name);

CREATE TABLE Jobs (
	ID			STRING(36) NOT NULL,
	Type			STRING(1000) NOT NULL,
	Workflow		STRING(1000) NOT NULL,
	Namespace		STRING(1000) NOT NULL,
	BugID			STRING(1000),
	Description		STRING(1000) NOT NULL,
	Link			STRING(1000) NOT NULL,
	Created			TIMESTAMP NOT NULL,
	Started			TIMESTAMP,
	Finished		TIMESTAMP,
	LLMModel		STRING(1000),
	CodeRevision		STRING(1000),
	Error			STRING(MAX),
	Args			JSON,
	Results			JSON,

	CONSTRAINT Jobs_TypeEnum CHECK (Type IN ('patching', 'moderation')),
	CONSTRAINT FK_JobWorkflow FOREIGN KEY (Workflow) REFERENCES Workflows (Name),
) PRIMARY KEY (ID);

CREATE TABLE TrajectorySpans (
	JobID			STRING(36) NOT NULL,
	Seq			INT64 NOT NULL,
	Nesting 		INT64 NOT NULL,
	Type 			STRING(1000) NOT NULL,
	Name			STRING(1000) NOT NULL,
	Timestamp		TIMESTAMP NOT NULL,
	Finished		BOOL NOT NULL,
	Duration		INT64,
	Error			STRING(1000),
	Args			JSON,
	Results			JSON,
	Instruction		STRING(MAX),
	Prompt			STRING(MAX),
	Reply			STRING(MAX),
	Thoughts		STRING(MAX),

	CONSTRAINT TrajectorySpans_TypeEnum CHECK (Type IN ('flow', 'action', 'agent', 'llm', 'tool')),
	CONSTRAINT FK_EventJob FOREIGN KEY (JobID) REFERENCES Jobs (ID),
) PRIMARY KEY (JobID, Seq);
