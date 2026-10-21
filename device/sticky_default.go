//go:build !linux

package device

import (
	"github.com/netbirdio/wireguard-go/conn"
	"github.com/netbirdio/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
