package agent

func (t *ToolSet) SetGaryWorkControl(kill func(int64) error, steer func(int64, string) error) {
	t.killWork = kill
	t.steerWork = steer
}
