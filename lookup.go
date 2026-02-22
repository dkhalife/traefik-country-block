package traefik_country_block

//go:generate go run ./cmd/generate

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
)

type ipv4Entry struct {
	from    uint32
	country uint8
}

type ipv6Entry struct {
	fromHi  uint64
	fromLo  uint64
	country uint8
}

var (
	geoOnce     sync.Once
	ipv4Entries []ipv4Entry
	ipv6Entries []ipv6Entry
)

func ensureInit() {
	geoOnce.Do(func() {
		ipv4Entries = decodeIPv4Data()
		ipv6Entries = decodeIPv6Data()
	})
}

func decodeIPv4Data() []ipv4Entry {
	if geoIPv4Data == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(geoIPv4Data)
	if err != nil {
		return nil
	}
	n := len(data) / 5
	entries := make([]ipv4Entry, n)
	for i := 0; i < n; i++ {
		off := i * 5
		entries[i] = ipv4Entry{
			from:    binary.BigEndian.Uint32(data[off : off+4]),
			country: data[off+4],
		}
	}
	return entries
}

func decodeIPv6Data() []ipv6Entry {
	if geoIPv6Data == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(geoIPv6Data)
	if err != nil {
		return nil
	}
	n := len(data) / 17
	entries := make([]ipv6Entry, n)
	for i := 0; i < n; i++ {
		off := i * 17
		entries[i] = ipv6Entry{
			fromHi:  binary.BigEndian.Uint64(data[off : off+8]),
			fromLo:  binary.BigEndian.Uint64(data[off+8 : off+16]),
			country: data[off+16],
		}
	}
	return entries
}

func lookupCountry(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("country lookup failed for %q: invalid IP", ipStr)
	}

	if v4 := ip.To4(); v4 != nil {
		num := binary.BigEndian.Uint32(v4)
		return lookupIPv4(num), nil
	}

	v6 := ip.To16()
	if v6 == nil {
		return "", fmt.Errorf("country lookup failed for %q: invalid IP", ipStr)
	}

	// 6to4 addresses (2002::/16): extract embedded IPv4
	if v6[0] == 0x20 && v6[1] == 0x02 {
		num := binary.BigEndian.Uint32(v6[2:6])
		return lookupIPv4(num), nil
	}

	// Teredo addresses (2001:0000::/32): client IPv4 is bitwise NOT of last 4 bytes
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00 {
		b := [4]byte{^v6[12], ^v6[13], ^v6[14], ^v6[15]}
		num := binary.BigEndian.Uint32(b[:])
		return lookupIPv4(num), nil
	}

	// Regular IPv6: convert to ip2location's uint128 representation.
	// ip2location reverses the 16 bytes then interprets as big-endian uint128,
	// which is equivalent to reading as little-endian with swapped halves.
	hi := binary.LittleEndian.Uint64(v6[8:16])
	lo := binary.LittleEndian.Uint64(v6[0:8])

	return lookupIPv6(hi, lo), nil
}

func lookupIPv4(num uint32) string {
	ensureInit()
	if len(ipv4Entries) == 0 {
		return "-"
	}
	idx := sort.Search(len(ipv4Entries), func(i int) bool {
		return ipv4Entries[i].from > num
	}) - 1
	if idx < 0 {
		return "-"
	}
	ci := ipv4Entries[idx].country
	if int(ci) >= len(geoCountryCodes) {
		return "-"
	}
	return geoCountryCodes[ci]
}

func lookupIPv6(hi, lo uint64) string {
	ensureInit()
	if len(ipv6Entries) == 0 {
		return "-"
	}
	idx := sort.Search(len(ipv6Entries), func(i int) bool {
		e := ipv6Entries[i]
		if e.fromHi != hi {
			return e.fromHi > hi
		}
		return e.fromLo > lo
	}) - 1
	if idx < 0 {
		return "-"
	}
	ci := ipv6Entries[idx].country
	if int(ci) >= len(geoCountryCodes) {
		return "-"
	}
	return geoCountryCodes[ci]
}
