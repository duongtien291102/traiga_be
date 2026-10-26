package model

// SRSAuthPayload webhook payload từ SRS
type SRSAuthPayload struct {
	ServerID string `json:"server_id"`
	Action   string `json:"action"`
	ClientID any    `json:"client_id"`
	IP       string `json:"ip"`
	VHost    string `json:"vhost"`
	App      string `json:"app"`
	Stream   string `json:"stream"`
	Name     string `json:"name"`
	Param    string `json:"param"`
	Cwd      string `json:"cwd"`
	File     string `json:"file"`
}
