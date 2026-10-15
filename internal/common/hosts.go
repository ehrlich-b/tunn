package common

import "time"

// Host registration deliberately excludes targets, commands, and credentials.
type HostEndpointSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type HostManifest struct {
	Machine string             `json:"machine"`
	Tunnels []HostEndpointSpec `json:"tunnels"`
}

type HostEndpoint struct {
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	URL           string    `json:"url"`
	Online        bool      `json:"online"`
	LastSeen      time.Time `json:"last_seen"`
	Access        string    `json:"access,omitempty"`
	EndpointToken bool      `json:"endpoint_token,omitempty"`
}

type Machine struct {
	Name     string         `json:"name"`
	Online   bool           `json:"online"`
	LastSeen time.Time      `json:"last_seen"`
	Tunnels  []HostEndpoint `json:"tunnels"`
}
