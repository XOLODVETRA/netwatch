// Package netutil помогает работать с локальными интерфейсами и адресами.
package netutil

import (
	"net"
	"net/netip"
)

// LocalIPs возвращает адреса поднятых интерфейсов, кроме loopback.
func LocalIPs() ([]netip.Addr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := toAddr(a)
			if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip.Unmap())
		}
	}
	return out, nil
}

// Iface — описание интерфейса для вывода списка.
type Iface struct {
	Name  string
	Addrs []string
	Flags net.Flags
}

// Interfaces возвращает список интерфейсов вместе с их адресами.
func Interfaces() ([]Iface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			addrs = nil
		}
		list := make([]string, 0, len(addrs))
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				list = append(list, v.IP.String())
			case *net.IPAddr:
				list = append(list, v.IP.String())
			}
		}
		out = append(out, Iface{Name: iface.Name, Addrs: list, Flags: iface.Flags})
	}
	return out, nil
}

// FirstInterface возвращает имя первого поднятого не-loopback интерфейса.
func FirstInterface() string {
	list, err := Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range list {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		return iface.Name
	}
	return ""
}

func toAddr(a net.Addr) netip.Addr {
	var raw net.IP
	switch v := a.(type) {
	case *net.IPNet:
		raw = v.IP
	case *net.IPAddr:
		raw = v.IP
	default:
		return netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}
