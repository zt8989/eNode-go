package ed2k

import (
	"encoding/binary"
	"net"
)

// Address helpers operate on net.IP rather than dotted-quad strings.
//
// A dual-stack listener reports an IPv4 peer as the mapped form ::ffff:a.b.c.d.
// The string parser IPv4ToInt32LE (misc.go) rejects that and callers substitute
// 0, so on a dual-stack bind every IPv4 client would silently lose its address.
// These helpers normalise the family first, so a mapped v4 peer is treated as
// plain IPv4 and a genuine v6 peer yields its 16 raw bytes.

// NormalizeIP collapses an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its
// 4-byte IPv4 form and returns genuine IPv6 addresses in 16-byte form. It
// returns nil for a nil/invalid input.
func NormalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

// IPv4ToUint32LE packs an IPv4 (or IPv4-mapped) address into the eD2K ClientID
// convention: the first octet is the low byte, matching the string parser
// IPv4ToInt32LE and eMule's GetIP(). It reports false for a genuine IPv6 address,
// which has no 32-bit representation and therefore no HighID.
func IPv4ToUint32LE(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(v4), true
}

// IPv6Bytes returns the 16 raw network-order bytes of a genuine IPv6 address —
// the exact form carried in the CT_MOD_IP_V6 tag and the sentinel source. It
// reports false for an IPv4 or IPv4-mapped address, which belongs in the uint32
// field instead; callers must not conflate the two, since a mapped-form blob
// would compare unequal to the semantically identical IPv4 on the client side.
func IPv6Bytes(ip net.IP) ([16]byte, bool) {
	var out [16]byte
	if ip == nil || ip.To4() != nil {
		return out, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return out, false
	}
	copy(out[:], v6)
	return out, true
}

// IsPublicIPv6 reports whether ip is a globally routable IPv6 address suitable to
// record as a reachable source. It rejects IPv4/mapped addresses, the loopback,
// link-local (fe80::/10), unique-local (fc00::/7), multicast and the unspecified
// address — none of which another peer could connect to.
func IsPublicIPv6(ip net.IP) bool {
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// ParsePublicIPv6 parses a textual IPv6 address and returns its 16 bytes only if
// it is globally routable. Used for the server's configured/auto-detected public
// IPv6.
func ParsePublicIPv6(s string) ([16]byte, bool) {
	var out [16]byte
	ip := net.ParseIP(s)
	if !IsPublicIPv6(ip) {
		return out, false
	}
	return IPv6Bytes(ip)
}
