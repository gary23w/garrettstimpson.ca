package notify

type Snapshot struct {
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`

	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string

	Assets []string

	DetailURL string

	FromStatus string
	ToStatus   string
}

func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(Unnamed vulnerability)"
}

type Message struct {
	Items []Item

	Batch bool

	WindowMinutes int

	HomeURL string
}
