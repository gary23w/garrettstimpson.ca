package agent

import (
	"context"
	"errors"
	"fmt"
)

type AbortCause struct {
	Code  string
	Short string
	Text  string
}

func (c *AbortCause) Error() string { return c.Text }

func cause(code, short, text string) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: text}
}

func Causef(code, short, format string, args ...any) *AbortCause {
	return &AbortCause{Code: code, Short: short, Text: fmt.Sprintf(format, args...)}
}

var (
	AbortPausedByUser = cause("paused_by_user", "User paused task",
		"The user paused the task through the task control interface (POST /api/tasks/{id}/control, action=pause). This Planner/Worker run was automatically canceled; the running intention will be returned to frontier(open), and after the task is restored, it will be picked up again and executed from the beginning.")
	AbortPausedByOrchestrator = cause("paused_by_orchestrator", "The orchestration agent paused the task",
		"The orchestration agent called the pause_task tool to pause this task. This Planner/Worker run was actively canceled; the running intention will be returned to frontier(open) and re-executed after recovery.")
	AbortTaskDeleted = cause("task_deleted", "Task deleted",
		"The task is being deleted (DELETE /api/tasks/{id}), and the deletion barrier has canceled the running Planner, Worker and main Agent of the task; the results of this operation will no longer be used.")
	AbortPausedOnReload = cause("paused_on_reload", "The backend resumes the paused state of the task",
		"When the backend starts, the task suspension is resumed based on the state persisted in the database. This run was canceled; under normal circumstances there is no running Agent during the recovery phase")
	AbortGoalMet = cause("goal_met", "The planner determines that the mission objectives have been achieved",
		"The planner determines that the task goal has been achieved and sets the task to done, then cancels the still running Worker; these intentions will be marked as stopped rather than failed")
	AbortSettleDrainTimeout = cause("settle_drain_timeout", "The waiting time for task timeout completion has been exhausted",
		"After the task reaches timeout, it waits for the running Worker to finish gracefully, but the 90-second drain grace is still insufficient, so a hard cancellation is performed; the intent will be marked as exhausted, and the facts and assets that have been written during the closing phase will be retained.")

	AbortKilledByPlanner = cause("killed_by_planner", "planners terminated this intention",
		"The planner calls kill_work to actively terminate this intention, which usually means that the direction has deviated or has no further value; the intention will be marked as stopped and will not be automatically reacquired.")
	AbortWorkPausedByUser = cause("work_paused_by_user", "The user paused this Worker intent",
		"The user paused a running Worker. This call is canceled and the intention is changed to paused; all registered intentions, facts, vulnerabilities and activity records are retained and can be re-executed from the beginning after recovery.")
	AbortWorkCancelledByUser = cause("work_cancelled_by_user", "The user deleted this Worker intent",
		"The user deleted a running Worker. This call is canceled; after the Worker exits the writing area, the server processes the intent according to the deletion mode selected by the user - false deletion is only marked as deleted and all outputs are retained, true deletion will cascade remove the intent and only the downstream nodes supported by it")
	AbortWorkFinished = cause("work_finished", "The worker has ended normally and released the context",
		"The Worker has ended normally and the engine releases its context resources in detachWork. This is not a runtime interrupt; if it appears in the interrupt message, it means there is a race condition between the cancellation and closing events.")
	AbortPausedRaceGuard = cause("paused_race_guard", "Refuse to start new run while task is paused",
		"When the task is in a suspended state, the engine refuses to issue a new execution context, which is used to prevent the race condition between claim and suspension from causing the Worker to continue to start; the claimed intention will be returned to the frontier")

	AbortChatStoppedByUser = cause("chat_stopped_by_user", "User stopped this conversation",
		"The user clicks Stop to actively terminate the current round of main Agent or session Agent. The activity records that have been generated will be retained and you can continue to send the next message.")
	AbortChatPausedWithTask = cause("chat_paused_with_task", "Task paused and aborted the main Agent conversation",
		"When the user pauses the task, the running main Agent conversation is also canceled simultaneously. The activity records that have been generated will be retained; the current round of messages will not be automatically replayed after the task is resumed.")
	AbortChatTurnFinished = cause("chat_turn_finished", "This round of dialogue has ended normally and the context has been released",
		"This round of dialogue has ended normally, and the server is releasing the context resources of this round. This is not a runtime interrupt; if it appears in the interrupt message, it means there is a race condition between the cancellation and closing events.")

	AbortShutdown = cause("shutdown", "Backend process is shutting down",
		"The backend process received SIGINT or SIGTERM and is restarting, updating, or shutting down. All running Agents will be canceled; remaining running intentions after restarting will be reset to open and re-executed.")
	AbortRunHardTimeout = cause("run_hard_timeout", "Single run hard timeout has been triggered",
		"A single run exceeds the soft wall clock budget and additional grace, indicating that the model request or a tool has not returned for a long time, resulting in the normal round boundary closing being unable to be executed. Please focus on checking the last tool call that did not return before the interruption.")
)

func AbortReason(ctx context.Context) (code, short, text string, ok bool) {
	c := context.Cause(ctx)
	if c == nil {
		return "", "", "", false
	}
	var ac *AbortCause
	if errors.As(c, &ac) {
		return ac.Code, ac.Short, ac.Text, true
	}
	switch {
	case errors.Is(c, context.DeadlineExceeded):
		return "deadline_exceeded", "Upstream context reaches deadline",
			"The upstream context reached the deadline, but the setter did not attach a named reason via WithTimeoutCause:" + c.Error(), true
	case errors.Is(c, context.Canceled):
		return "canceled_no_cause", "The canceling party did not attach a named reason",
			"The upstream context was canceled, but the canceling party did not attach a named reason through context.WithCancelCause; please register the reason at agent/cancelcause.go and access the cancellation point", true
	default:
		return "other", firstLine(c.Error(), 80), c.Error(), true
	}
}
