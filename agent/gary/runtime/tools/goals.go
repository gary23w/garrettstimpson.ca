package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/agentcore"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/llm"
	acperm "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/permission"
	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/transcript"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

const goalsDefaultTmpl = "You are a penetration testing target decomposer. Your job is to identify the **ultimate result** from user input, not to plan the attack steps.\n\n**The first step (do it before splitting the target): Extract operational constraints**\nIdentify the operator's clear regulations on [what operations can and cannot be done] from the \"task goal/task description\", and call set_constraints to register them one by one (if the description and goal do not involve operation constraints, you do not need to extract the operation constraints):\n- type=deny: prohibited operations (such as \"no port scanning\", \"no write/deletion operations on the production environment\", \"no blasting\", \"no touching a certain subdomain\").\n- type=allow: clearly allowed/limited operation scope (such as \"only allow passive reconnaissance\" \"only for a certain domain name\").\n- Constraint ≠ target, also ≠ attack step: it is the regulation of the boundaries of operational behavior.\n- **Constraints must be [self-contained, hard-coded specific goals]**: Replace **referential words** such as \"current target/current port/current IP/current domain name/this site\" with **specific values** in the task goal/description. Constraints will be injected separately into the prompts in the execution phase, and it is impossible to determine who the referent refers to after being separated from the context.\n  Example: The target is https://abc.example.net → write \"Only allow testing abc.example.net\" instead of \"Only allow testing of the current target\"; \"Only test target port 443, do not scan other ports\" instead of \"Only test the current port\". If the original text only says \"current target\" but the target address is clear, fill in the address.\n- **Only register the constraints that are [clearly written or emphasized] in the target/description, and it is strictly forbidden to make up**; use deny (more conservative) when you are not sure about the type.\n- Don't call set_constraints if there are indeed no operational constraints in the target/description.\nAfter registering the constraints (if any), proceed with the following target splitting.\n\n**Goal = Final deliverable/verifiable result**\n\n**Content that is not a goal (not allowed as a sub-goal)**:\n- Information collection, reconnaissance, endpoint scanning\n- Vulnerability analysis and verification process\n- Attack steps and exploitation methods\n- Result verification steps\n\n**Split Principle**:\n- There is only one ultimate goal described by the user → output one\n- There are multiple **independent** final deliverables → listed separately\n- Annotation vulnclass that can correspond to a clear vulnerability class; leave information collection/business logic targets blank\n- It is strictly prohibited to invent goals that have not been mentioned by the user\n\nCall set_goals to submit the results."

const goalsScopeTail = "**Additional Responsibilities: Register Test Asset Scope**\nIn addition to splitting the goals, you must also identify the **clearly given test asset scope** from the \"task goal/task description\" and call add_task_scope to register (the authorization boundary of this task is also the denominator of the asset test coverage). ** Minimum scope principle: Only register the target that the user has clearly clicked on, and never enlarge it without authorization. **\n- The target is a URL or an address with a hostname (such as https://xxx.example.com/path, app.example.com) → take its **full hostname**, kind=subdomain, value=full hostname.\n  Example: Target https://a1b2c3.lab.example.net/path → kind=subdomain, value=a1b2c3.lab.example.net (**not** example.net).\n  **It is strictly prohibited** to shorten the host name with subdomains to the root domain name - registering the entire example.com when you see xxx.example.com will expand the scope beyond the user's target, violating the principle of minimum scope.\n- Use kind=root_domain, value=example.com only when the user gives a **bare root domain name and does not include any subdomain** (such as writing example.com directly), or explicitly says \"entire site/all subdomains/full domain name\" →.\n- Pure IP or network segment → kind=ip/cidr, value=IP or CIDR.\n- **Don't** register the company scope (company) - the task has just been created and the company usually does not exist in the asset system, so it cannot be registered, and the company-level scope will be processed in the subsequent plan stage.\nOther rules:\n- Only register the scope of the target/description that is clearly stated; inventing or inferring unmentioned domain names/IPs is strictly prohibited.\n- reason briefly states which sentence the basis comes from to facilitate auditing.\n- **Don't** call add_task_scope without any explicit asset scope in the target/description.\nFirst use add_task_scope to register the scope (if any), and then call set_goals to submit the goal."

type GoalSpec struct {
	Text      string `json:"text"`
	VulnClass string `json:"vulnclass,omitempty"`
}

func DecomposeGoals(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}
	return DecomposeGoalsWithProvider(ctx, prov, dataDir, goalText, desc, as, ts, taskID, false, 0, emit)
}

func DecomposeGoalsWithProvider(ctx context.Context, prov llm.Provider, dataDir, goalText, desc string, as *db.AssetStore, ts *db.ExplorationStore, taskID int64, nonStreaming bool, maxTokens int, emit func(db.Activity)) []GoalSpec {
	if prov == nil {
		return nil
	}

	if ts != nil {
		ctx = transcript.WithSessionID(ctx, fmt.Sprintf("exp%d-goals", ts.ID()))
	}

	tsx := &ToolSet{as: as, ts: ts, taskID: taskID, worker: "goals"}

	sys := renderSystem("goals", goalsDefaultTmpl, GoalsVars{DataDir: dataDir, Now: nowStr()})

	tools := []actool.CoreTool{tsx.setGoals(), tsx.setConstraints()}

	if as != nil && taskID > 0 {
		tools = append(tools, tsx.addTaskScope())
		sys += goalsScopeTail
	}
	userMsg := "Mission objectives:" + goalText
	if d := strings.TrimSpace(desc); d != "" {
		userMsg += "Mission description (background information, may include target range/number of flags/engagement instructions; for reference only, do not infer content not mentioned in it):" + d
	}

	captureEmit := func(r db.Activity) {
		if emit != nil {
			r.Worker = "planner"
			emit(r)
		}
	}
	captureRun(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{sys},
		Tools:                  tools,
		PermissionMode:         acperm.ModeBypass,
		DisableBackgroundTasks: true,

		MaxTurns:     8,
		NonStreaming: nonStreaming,
		MaxTokens:    maxTokens,
	}, userMsg, captureEmit)

	if ts == nil {
		return nil
	}
	nodes, _ := ts.ListByKind(db.KindGoal, 10000)
	var out []GoalSpec
	for _, n := range nodes {
		var p struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		if strings.TrimSpace(p.Text) != "" {
			out = append(out, GoalSpec{Text: p.Text, VulnClass: p.VulnClass})
		}
	}
	return out
}
