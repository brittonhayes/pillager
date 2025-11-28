package c2

import (
	"context"
	"time"

	"github.com/brittonhayes/pillager"
)

// C2Client defines the interface for C2 framework integrations.
//
// Supported frameworks:
// - Sliver (https://github.com/BishopFox/sliver)
// - Mythic (https://github.com/its-a-feature/Mythic)
// - Covenant (https://github.com/cobbr/Covenant)
// - Custom HTTP-based C2
//
// WARNING: C2 integration is designed for AUTHORIZED RED TEAM OPERATIONS ONLY.
// Unauthorized use constitutes malicious activity and may violate laws.
type C2Client interface {
	// Register announces the scanner to the C2 server and establishes session.
	// Returns an error if registration fails.
	Register(ctx context.Context) error

	// SendFindings transmits discovered findings to the C2 server.
	// Findings are associated with the current session/callback.
	SendFindings(ctx context.Context, findings []pillager.Finding) error

	// Beacon sends a periodic heartbeat to the C2 server.
	// This maintains session liveness and checks for new tasks.
	Beacon(ctx context.Context) error

	// GetTasks retrieves pending commands/tasks from the C2 server.
	// Returns a list of tasks to be executed.
	GetTasks(ctx context.Context) ([]Task, error)

	// SendTaskResult reports the result of task execution back to C2.
	SendTaskResult(ctx context.Context, taskID string, result TaskResult) error

	// Unregister cleanly disconnects from the C2 server.
	// Should be called before shutdown.
	Unregister(ctx context.Context) error
}

// Task represents a command from the C2 server.
type Task struct {
	// ID is the unique task identifier
	ID string

	// Type specifies the task type
	Type TaskType

	// Command is the command to execute
	Command string

	// Arguments are task-specific arguments
	Arguments map[string]interface{}

	// Timeout is the maximum execution time
	Timeout time.Duration

	// Priority affects task scheduling
	Priority int
}

// TaskType defines the type of task.
type TaskType string

const (
	// TaskTypeScan triggers a new scan operation
	TaskTypeScan TaskType = "scan"

	// TaskTypeUpload uploads findings or files
	TaskTypeUpload TaskType = "upload"

	// TaskTypeExecute executes a shell command
	TaskTypeExecute TaskType = "execute"

	// TaskTypeConfig updates scanner configuration
	TaskTypeConfig TaskType = "config"

	// TaskTypeSleep changes beacon interval
	TaskTypeSleep TaskType = "sleep"

	// TaskTypeExit terminates the scanner
	TaskTypeExit TaskType = "exit"
)

// TaskResult represents the result of task execution.
type TaskResult struct {
	// TaskID is the ID of the completed task
	TaskID string

	// Success indicates whether the task completed successfully
	Success bool

	// Output contains the task output
	Output string

	// Error contains error information if task failed
	Error string

	// Metadata contains task-specific metadata
	Metadata map[string]interface{}

	// Duration is how long the task took to execute
	Duration time.Duration
}

// Config holds C2 configuration.
type Config struct {
	// Framework specifies the C2 framework
	Framework Framework

	// BeaconMode specifies how beaconing works
	BeaconMode BeaconMode

	// BeaconInterval is the time between beacons
	BeaconInterval time.Duration

	// BeaconJitter is randomization added to beacon interval
	BeaconJitter time.Duration

	// AutoTasks enables automatic task execution
	AutoTasks bool

	// AutoTaskConfig maps finding types to commands
	AutoTaskConfig map[string][]string

	// Options holds framework-specific configuration
	Options map[string]interface{}
}

// Framework identifies the C2 framework.
type Framework string

const (
	// FrameworkSliver is the Sliver C2 framework
	FrameworkSliver Framework = "sliver"

	// FrameworkMythic is the Mythic C2 framework
	FrameworkMythic Framework = "mythic"

	// FrameworkCovenant is the Covenant C2 framework
	FrameworkCovenant Framework = "covenant"

	// FrameworkHTTP is a generic HTTP-based C2
	FrameworkHTTP Framework = "http"

	// FrameworkCustom is a custom C2 implementation
	FrameworkCustom Framework = "custom"
)

// BeaconMode defines how beaconing operates.
type BeaconMode string

const (
	// BeaconModeSingle sends a single beacon and exits
	BeaconModeSingle BeaconMode = "single"

	// BeaconModeContinuous sends beacons on a regular interval
	BeaconModeContinuous BeaconMode = "continuous"

	// BeaconModeScheduled uses cron-like scheduling
	BeaconModeScheduled BeaconMode = "scheduled"
)

// SessionInfo holds information about the C2 session.
type SessionInfo struct {
	// SessionID is the unique session identifier
	SessionID string

	// CallbackID is the callback identifier (Mythic-specific)
	CallbackID string

	// GruntID is the grunt identifier (Covenant-specific)
	GruntID string

	// ImplantID is the implant identifier (Sliver-specific)
	ImplantID string

	// Hostname is the hostname where scanner is running
	Hostname string

	// Username is the user running the scanner
	Username string

	// OS is the operating system
	OS string

	// Architecture is the system architecture
	Architecture string

	// RegisteredAt is when the session was registered
	RegisteredAt time.Time

	// LastBeacon is the time of the last beacon
	LastBeacon time.Time
}

// Registry holds registered C2 client factories.
type Registry struct {
	factories map[Framework]Factory
}

// Factory creates C2 client instances.
type Factory func(config Config) (C2Client, error)

// NewRegistry creates a new C2 client registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[Framework]Factory),
	}
}

// Register registers a C2 client factory for a given framework.
func (r *Registry) Register(framework Framework, factory Factory) {
	r.factories[framework] = factory
}

// Create creates a C2 client instance for the given configuration.
func (r *Registry) Create(config Config) (C2Client, error) {
	factory, ok := r.factories[config.Framework]
	if !ok {
		return nil, &UnsupportedFrameworkError{Framework: config.Framework}
	}
	return factory(config)
}

// UnsupportedFrameworkError is returned when an unknown framework is requested.
type UnsupportedFrameworkError struct {
	Framework Framework
}

func (e *UnsupportedFrameworkError) Error() string {
	return "unsupported c2 framework: " + string(e.Framework)
}

// DefaultRegistry is the global C2 client registry.
var DefaultRegistry = NewRegistry()

// Create creates a C2 client using the default registry.
func Create(config Config) (C2Client, error) {
	return DefaultRegistry.Create(config)
}

// BeaconScheduler manages periodic beaconing to the C2 server.
type BeaconScheduler struct {
	client   C2Client
	config   Config
	stopChan chan struct{}
	doneChan chan struct{}
}

// NewBeaconScheduler creates a new beacon scheduler.
func NewBeaconScheduler(client C2Client, config Config) *BeaconScheduler {
	return &BeaconScheduler{
		client:   client,
		config:   config,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// Start begins the beaconing schedule.
func (s *BeaconScheduler) Start(ctx context.Context) error {
	defer close(s.doneChan)

	switch s.config.BeaconMode {
	case BeaconModeSingle:
		return s.client.Beacon(ctx)

	case BeaconModeContinuous:
		return s.beaconContinuous(ctx)

	case BeaconModeScheduled:
		return s.beaconScheduled(ctx)

	default:
		return &InvalidBeaconModeError{Mode: s.config.BeaconMode}
	}
}

// Stop stops the beaconing schedule.
func (s *BeaconScheduler) Stop() {
	close(s.stopChan)
	<-s.doneChan
}

// beaconContinuous sends beacons on a regular interval with jitter.
func (s *BeaconScheduler) beaconContinuous(ctx context.Context) error {
	ticker := time.NewTicker(s.config.BeaconInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-s.stopChan:
			return nil

		case <-ticker.C:
			// Add jitter to avoid predictable timing
			jitter := time.Duration(0)
			if s.config.BeaconJitter > 0 {
				// Simple jitter: random ± jitter
				// In production, use crypto/rand for better randomness
				jitter = s.config.BeaconJitter / 2
			}

			time.Sleep(jitter)

			// Send beacon
			if err := s.client.Beacon(ctx); err != nil {
				// Log error but continue beaconing
				// In production, implement retry logic
				continue
			}

			// Check for tasks if auto-tasks enabled
			if s.config.AutoTasks {
				tasks, err := s.client.GetTasks(ctx)
				if err != nil {
					continue
				}

				// Execute tasks
				for _, task := range tasks {
					// In production, execute tasks in goroutines
					// For now, skip implementation
					_ = task
				}
			}
		}
	}
}

// beaconScheduled sends beacons based on a cron schedule.
func (s *BeaconScheduler) beaconScheduled(ctx context.Context) error {
	// Placeholder - would implement cron scheduling
	return &NotImplementedError{Feature: "scheduled beaconing"}
}

// InvalidBeaconModeError is returned for invalid beacon modes.
type InvalidBeaconModeError struct {
	Mode BeaconMode
}

func (e *InvalidBeaconModeError) Error() string {
	return "invalid beacon mode: " + string(e.Mode)
}

// NotImplementedError is returned for unimplemented features.
type NotImplementedError struct {
	Feature string
}

func (e *NotImplementedError) Error() string {
	return "not implemented: " + e.Feature
}

// AutoTaskExecutor executes tasks automatically based on findings.
type AutoTaskExecutor struct {
	client C2Client
	config map[string][]string // Maps finding types to commands
}

// NewAutoTaskExecutor creates a new auto-task executor.
func NewAutoTaskExecutor(client C2Client, config map[string][]string) *AutoTaskExecutor {
	return &AutoTaskExecutor{
		client: client,
		config: config,
	}
}

// Execute executes auto-tasks for a finding.
func (e *AutoTaskExecutor) Execute(ctx context.Context, finding pillager.Finding) error {
	// Look up commands for this finding type
	commands, ok := e.config[finding.Description]
	if !ok {
		return nil // No auto-tasks configured for this finding
	}

	// Execute each command
	for _, command := range commands {
		task := Task{
			Type:    TaskTypeExecute,
			Command: command,
			Arguments: map[string]interface{}{
				"finding": finding,
			},
		}

		// In production, this would actually execute the task
		_ = task
	}

	return nil
}
