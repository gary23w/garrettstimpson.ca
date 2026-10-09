package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	actool "github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/engine/tool"
	"github.com/gary23w/garrettstimpson.ca/agent/gary/runtime/storage"
)

func assetInterceptCandidates(item assetInputItem) (domains, ips, urls []string) {
	add := func(dst *[]string, s string) {
		if s = strings.TrimSpace(s); s != "" {
			*dst = append(*dst, s)
		}
	}
	add(&domains, item.Domain)
	for _, d := range item.BoundDomains {
		add(&domains, d)
	}
	add(&ips, item.IP)
	add(&ips, item.ServiceIP)
	add(&urls, item.URL)
	if item.URL != "" {
		if u, err := url.Parse(item.URL); err == nil {
			if h := u.Hostname(); h != "" {
				if net.ParseIP(h) != nil {
					add(&ips, h)
				} else {
					add(&domains, h)
				}
			}
		}
	}
	return domains, ips, urls
}

func assetInputLabel(item assetInputItem) string {
	typ := strings.TrimSpace(item.Type)
	var target string
	switch {
	case strings.TrimSpace(item.Domain) != "":
		target = strings.TrimSpace(item.Domain)
	case strings.TrimSpace(item.URL) != "":
		target = strings.TrimSpace(item.URL)
	case strings.TrimSpace(item.IP) != "":
		target = strings.TrimSpace(item.IP)
	case strings.TrimSpace(item.ServiceIP) != "":
		target = strings.TrimSpace(item.ServiceIP)
	default:
		target = "(unknown)"
	}
	if typ != "" {
		return fmt.Sprintf("[%s] %s", typ, target)
	}
	return target
}

func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
}

type assetInputItem struct {
	Type string `json:"type"`

	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"`

	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"`

	Port  int    `json:"port"`
	Proto string `json:"proto"`

	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"Batch registration of newly discovered assets, multiple types can be mixed at one time (see enumeration for type)."+
			"Required fields for each type: root_domain→domain; ip→ip (must be IPv4/IPv6, not host name); subdomain→domain; app→app_name; service(HTTP)→url; service (non-HTTP)→service_name+port (fill in at least one ip/domain); endpoint→url+method. The meaning of the remaining fields can be found in their respective descriptions."+
			"auth/technologies/params is appended and does not overwrite the original value."+
			"Returns: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{

			"assets": map[string]any{
				"type":        "array",
				"description": "Asset array, each element corresponds to an asset record",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "Asset type",
					},

					"domain":      str("Root domain name or subdomain name (root_domain/subdomain required)"),
					"icp":         str("ICP registration number (optional)"),
					"record_type": str("DNS resolution type: A/AAAA/CNAME/MX, etc. (subdomain optional)"),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of DNS resolution values (subdomain is optional, such as [\"1.2.3.4\",\"2.3.4.5\"])",
					},

					"ip": str("IP address must be an IPv4/IPv6 address, and the host name cannot be filled in (please use the domain field of type=subdomain for the host name); the ip type is required; the service/endpoint type can be filled in and is used to associate IP"),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "List of domain names bound to this IP (ip type optional)",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "Open port list (ip type optional)",
						"items": obj(map[string]any{
							"port":    intp("port number"),
							"service": str("Service name, such as http/ssh/mysql, etc. (optional)"),
						}, "port"),
					},

					"app_name":    str("Application name (required for app type)"),
					"bundle_id":   str("Bundle ID (optional for app type)"),
					"category":    str("Application classification (optional)"),
					"description": str("Application description (optional)"),
					"app_icp":     str("Apply ICP filing (optional)"),
					"company_id":  intp("Attributing company id (optional for app type; app cannot be automatically attributed by scope and needs to be specified explicitly. id is returned by add_company_scope)"),

					"url":         str("Full URL, including protocol and port (required for HTTP service; service_type is automatically set to http)"),
					"status_code": intp("HTTP response status code, such as 200/301/403/404 (optional)"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "HTTP response body bytes (optional)",
					},
					"page_title":   str("Page title (optional)"),
					"favicon_mmh3": str("favicon MMH3 hash (optional)"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Fingerprint/technology stack list, such as [\"Nginx\", \"Vue\", \"Bootstrap\"] (optional)",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "A list of discovered authentication information, each containing fields such as type/username/password (optional, appending will not overwrite)",
						"items":       map[string]any{"type": "object"},
					},

					"service_name": str("Service name, such as ssh/mysql/redis (required when service is not HTTP)"),
					"port":         intp("Port number (required when service is not HTTP)"),

					"method": str("HTTP method: GET/POST/PUT/PATCH/DELETE, etc. (endpoint is required)"),
					"params": map[string]any{
						"type":        "array",
						"description": "Request parameter list, each containing location(query/body/header/path)/name/value/type (optional, appending will not overwrite)",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}

			taskID := t.taskID

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			blockRules, _ := t.as.ListAssetInterceptRules()
			var allowRules []db.AssetInterceptRule
			if t.taskID > 0 {
				if tb, ta, err := t.as.TaskInterceptRulesSplit(t.taskID); err == nil {
					blockRules = append(blockRules, tb...)
					allowRules = ta
				}
			}

			for i, item := range a.Assets {

				domains, ips, urls := assetInterceptCandidates(item)
				if d := db.EvaluateAssetGate(blockRules, allowRules, domains, ips, urls); !d.Allowed {
					errs = append(errs, errEntry{
						Index: i,
						Error: fmt.Sprintf("Asset %s %s, insertion disabled", assetInputLabel(item), d.Reason),
					})
					continue
				}

				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":

					if item.URL != "" {

						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
				if taskID > 0 {
					var sourceNodeID *int64
					if t.ownerNode > 0 {
						nodeID := t.ownerNode
						sourceNodeID = &nodeID
					}
					summary := "Agent is registered through insert_assets"
					if t.ownerNode > 0 {
						summary = fmt.Sprintf("Worker intent #%d is registered via insert_assets", t.ownerNode)
					}
					_ = t.as.SetTaskAssetSource(taskID, id, "agent", summary, sourceNodeID)
				}

				{
					svcIP := item.ServiceIP
					if svcIP == "" {
						svcIP = item.IP
					}
					_ = t.as.AddAutoScope(taskID, typ, item.Domain, item.URL, svcIP)
				}
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"Add the domain name/IP/CIDR/ICP registration/enterprise keywords to a company's [Asset Scope] - the domain name, network and ICP will automatically claim the hit assets, and the keywords are only provided to the Agent as a scope prompt."+
			"The company name is unique: If company does not exist, create a new one, and if it already exists, reuse it (only merge the scope)."+
			"Scope is one line at a time, and the system automatically identifies: root domain name / URL / single IP / CIDR network segment / ICP registration / enterprise keywords."+
			"Be sure to provide reason with the attribution basis (whois/certificate/ASN, etc.)."+
			"Guardrails: Reject naked TLDs and overly wide network segments (IPv4 prefixes must be /16-/32, IPv6 prefixes must be /32-/128), illegal lines will be skipped and returned in errors.",
		obj(map[string]any{
			"company": str("Company name (create if it does not exist, reuse if it exists; the name is unique)"),
			"scope":   str("Asset scope, one line per line: domain name / URL / IP / CIDR / ICP filing / enterprise keywords"),
			"reason":  str("Basis of attribution (evidence/source), must be filled in"),
			"logo":    str("Company icon URL (optional; only valid when creating a new company)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company cannot be empty"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("Failed to create/get company:" + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

func (t *ToolSet) addTaskScope() actool.CoreTool {
	return writeTool(
		"add_task_scope",
		"Add the test scope to [this task] - this is the authorization boundary of this task and also the denominator of asset test coverage."+
			"kind supports: company (assets under the entire company's name) / root_domain (the entire root domain, including all subdomains) / subdomain (a single precise subdomain) / ip / cidr / icp / keyword."+
			"Description: Hosts encountered by workers one by one will be [automatically] added to the scope (precise subdomain) by the system; this tool is used to [active expansion] - include the entire root domain/entire company, or additionally specify a certain subdomain/IP."+
			"value: company passes the company name or id (the company must already exist); root_domain/subdomain passes the domain name; ip/cidr passes the IP or network segment; icp/keyword passes the registration number or company keyword."+
			"Be sure to give reason a basis (auditable). Use the entries array for multiple entries.",
		obj(map[string]any{
			"entries": map[string]any{"type": "array", "description": "Batch: [{kind, value}]. kind∈company/root_domain/subdomain/ip/cidr/icp/keyword.", "items": map[string]any{"type": "object"}},
			"kind":    str("[Single entry] company/root_domain/subdomain/ip/cidr/icp/keyword"),
			"value":   str("[Single entry] Company name or id / domain name / IP / CIDR / ICP / keyword"),
			"reason":  str("Basis for joining (for auditing), be sure to fill in"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("add_task_scope not enabled: AssetStore not initialized"), nil
			}
			if t.taskID <= 0 {
				return actool.Errorf("add_task_scope requires task context (currently no task)"), nil
			}
			type scopeEntry struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			}
			var a struct {
				Entries []scopeEntry `json:"entries"`
				scopeEntry
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			items := a.Entries
			if len(items) == 0 {
				items = []scopeEntry{a.scopeEntry}
			}
			var added []map[string]any
			errs := map[string]string{}
			for i, e := range items {
				ts, err := t.as.AddAgentScope(t.taskID, strings.TrimSpace(e.Kind), e.Value, a.Reason, "agent")
				if err != nil {
					errs[strconv.Itoa(i)] = err.Error()
					continue
				}
				added = append(added, map[string]any{"kind": ts.Kind, "domain": ts.Domain, "net": ts.Net, "value": ts.Value, "company_id": ts.CompanyID})
			}
			out := map[string]any{"added": added}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		},
	)
}

func (t *ToolSet) listUntestedAssets() actool.CoreTool {
	return readTool(
		"list_untested_assets",
		"Query the assets within the scope of [this task and directly related tasks] that have not been covered by fact anchors (the related range is read-only, for you to judge whether to make a supplementary test, and does not make decisions for you)."+
			"Optional filtering by asset type: root_domain/subdomain/service/app/endpoint/ip."+
			"Pagination: page starts from 1, page_size defaults to 10. Return {assets:[{id,type,label}], total, page, page_size}. Only task context is available.",
		obj(map[string]any{
			"type":      str("Asset type filtering (optional): root_domain/subdomain/service/app/endpoint/ip"),
			"page":      intp("One-based page number, default 1"),
			"page_size": intp("Number per page (default 10)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_untested_assets not enabled: AssetStore not initialized"), nil
			}
			if t.taskID <= 0 || t.ts == nil {
				return actool.Errorf("list_untested_assets requires task context"), nil
			}
			var a struct {
				Type     string `json:"type"`
				Page     int    `json:"page"`
				PageSize int    `json:"page_size"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Page <= 0 {
				a.Page = 1
			}
			if a.PageSize <= 0 {
				a.PageSize = 10
			}
			offset := (a.Page - 1) * a.PageSize
			assets, total, err := t.as.ListUntestedAssetsWithSources(t.taskID, strings.TrimSpace(a.Type), a.PageSize, offset)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"assets": assets, "total": total, "page": a.Page, "page_size": a.PageSize,
			})
		},
	)
}

func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"Query the asset library: DSL expression search, or direct fetching by id/ids; paging is supported. Only assets within the test range of [this task and directly related tasks] will be returned."+
			"DSL: field=value fuzzy (ILIKE) | field==value precise | field!=value exclusion | numeric field support > >= < <= | bare words = full text fuzzy; AND/OR combination (AND has high priority), grouping with parentheses can be used. Asset types use independent type parameters and are not written into the DSL."+
			"When id/ids are not passed, dsl must be non-empty (unconditional full query is not allowed)."+
			"Available fields: domain (root/sub/service domain name), root_domain, ip, url, page_title, icp, service_name, app_name, method (such as GET/POST), service_type (http|other), record_type (such as A/CNAME), technology (array, = fuzzy == precise), port/status_code/company_id (integer)."+
			"Example: status_code>=400 AND technology=shiro; (port==80 OR port==443) AND technology=nginx",
		obj(map[string]any{
			"dsl":    str("DSL query expression (see tool description for syntax/fields). Must be non-empty if id/ids are not passed."),
			"type":   str("Asset type filtering: root_domain|ip|subdomain|app|service|endpoint (independent field, can be superimposed with dsl; type alone is not enough to query, dsl is still needed)"),
			"id":     intp("Get directly by individual asset id (optional, mutually exclusive with dsl/type)"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "Get directly by multiple asset IDs (optional, mutually exclusive with dsl/type)"},
			"limit":  intp("Result limit, default 10 (optional)"),
			"offset": intp("Paging offset, default 0 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, []int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDsInScope(t.taskID, a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSLInScope(a.DSL, a.Type, t.taskID, a.Limit, a.Offset)
			default:
				return actool.Errorf("When id/ids are not passed, dsl cannot be empty: unconditional query of all assets is not allowed, please provide query conditions"), nil
			}
			if err != nil {
				return actool.Errorf("DSL error:" + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"List the [enterprise/company] in the asset library, their asset scope and the number of vested assets. Used to see which companies,"+
			"Get company_id (used when insert_assets is associated with app and list_assets is filtered by company_id)."+
			"Optional search: fuzzy filter by company name (not case sensitive), leave blank to return all.",
		obj(map[string]any{
			"search": str("Fuzzy filter by company name (optional, case-insensitive); leave blank to return all"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("Failed to query company:" + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (t *ToolSet) WorkerTools() []actool.CoreTool {
	return []actool.CoreTool{

		t.listFindings(),
		t.addFinding(), t.recordFact(),

		t.insertAssets(), t.listAssets(),

		t.searchAllWorkerTraces(), t.getWorkerTrace(),

		t.nodeDetail(),
	}
}

func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.expandDigest(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),

		t.steerWorkTool(),

		t.setGoals(),

		t.setConstraints(),

		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		t.addFinding(), t.recordFact(),
		t.addTaskScope(),

		t.listUntestedAssets(),
	}
}

func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}
