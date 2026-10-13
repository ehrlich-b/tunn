package host

import _ "embed"

//go:embed templates/app-devices.html
var appDevicesHTML string

//go:embed templates/app-devices.js
var appDevicesJS string
