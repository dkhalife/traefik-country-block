package main

import (
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	binPath := flag.String("db", "./IP2LOCATION-LITE-DB1.BIN", "Path to IP2Location BIN file")
	output := flag.String("out", "./geodata.go", "Output Go file path")
	flag.Parse()

	f, err := os.Open(*binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Read 64-byte header (1-indexed in ip2location format, starts at file offset 0)
	header := make([]byte, 64)
	if _, err := f.ReadAt(header, 0); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading header: %v\n", err)
		os.Exit(1)
	}

	dbType := header[0]
	dbColumn := header[1]
	dbYear := header[2]
	dbMonth := header[3]
	dbDay := header[4]
	ipv4Count := binary.LittleEndian.Uint32(header[5:9])
	ipv4Addr := binary.LittleEndian.Uint32(header[9:13])
	ipv6Count := binary.LittleEndian.Uint32(header[13:17])
	ipv6Addr := binary.LittleEndian.Uint32(header[17:21])

	fmt.Printf("Database: type=%d columns=%d date=20%02d-%02d-%02d\n", dbType, dbColumn, dbYear, dbMonth, dbDay)
	fmt.Printf("IPv4: %d records at offset %d\n", ipv4Count, ipv4Addr)
	fmt.Printf("IPv6: %d records at offset %d\n", ipv6Count, ipv6Addr)

	// Column sizes (matching ip2location library)
	ipv4ColSize := uint32(dbColumn) * 4                    // 4 bytes per column
	ipv6ColSize := 16 + (uint32(dbColumn)-1)*4             // 16-byte IP + 4 bytes per remaining column

	// Country code index: 0 = "-" (unknown/unassigned)
	countryList := []string{"-"}
	countryMap := map[string]uint8{"-": 0}

	getIdx := func(cc string) uint8 {
		cc = strings.TrimSpace(cc)
		if cc == "" {
			cc = "-"
		}
		if idx, ok := countryMap[cc]; ok {
			return idx
		}
		idx := uint8(len(countryList))
		countryMap[cc] = idx
		countryList = append(countryList, cc)
		return idx
	}

	// Read a length-prefixed string from the file (0-indexed offset)
	readStr := func(ptr uint32) string {
		buf := make([]byte, 256)
		if _, err := f.ReadAt(buf, int64(ptr)); err != nil {
			return "-"
		}
		slen := buf[0]
		if slen == 0 {
			return "-"
		}
		return string(buf[1 : 1+slen])
	}

	// --- Read IPv4 records ---
	type v4rec struct {
		from    uint32
		country uint8
	}

	raw4 := make([]v4rec, 0, ipv4Count)
	for i := uint32(0); i < ipv4Count; i++ {
		// ipv4Addr is 1-indexed, convert to 0-indexed for ReadAt
		off := int64(ipv4Addr) + int64(i)*int64(ipv4ColSize) - 1
		row := make([]byte, ipv4ColSize)
		if _, err := f.ReadAt(row, off); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading IPv4 row %d: %v\n", i, err)
			os.Exit(1)
		}
		ipFrom := binary.LittleEndian.Uint32(row[0:4])
		cPtr := binary.LittleEndian.Uint32(row[4:8])
		cc := readStr(cPtr)
		raw4 = append(raw4, v4rec{from: ipFrom, country: getIdx(cc)})
	}

	// Merge consecutive same-country ranges
	merged4 := make([]v4rec, 0, len(raw4))
	for _, r := range raw4 {
		if len(merged4) == 0 || r.country != merged4[len(merged4)-1].country {
			merged4 = append(merged4, r)
		}
	}
	fmt.Printf("IPv4: %d -> %d merged\n", len(raw4), len(merged4))

	// --- Read IPv6 records ---
	type v6rec struct {
		hi, lo  uint64
		country uint8
	}

	raw6 := make([]v6rec, 0, ipv6Count)
	for i := uint32(0); i < ipv6Count; i++ {
		off := int64(ipv6Addr) + int64(i)*int64(ipv6ColSize) - 1
		row := make([]byte, ipv6ColSize)
		if _, err := f.ReadAt(row, off); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading IPv6 row %d: %v\n", i, err)
			os.Exit(1)
		}
		// ip_from is 16 bytes, interpreted as big-endian uint128 (Hi, Lo)
		hi := binary.BigEndian.Uint64(row[0:8])
		lo := binary.BigEndian.Uint64(row[8:16])
		cPtr := binary.LittleEndian.Uint32(row[16:20])
		cc := readStr(cPtr)
		raw6 = append(raw6, v6rec{hi: hi, lo: lo, country: getIdx(cc)})
	}

	merged6 := make([]v6rec, 0, len(raw6))
	for _, r := range raw6 {
		if len(merged6) == 0 || r.country != merged6[len(merged6)-1].country {
			merged6 = append(merged6, r)
		}
	}
	fmt.Printf("IPv6: %d -> %d merged\n", len(raw6), len(merged6))

	// --- Encode packed binary ---
	// IPv4: 5 bytes per entry [4B big-endian ip_from][1B country_idx]
	enc4 := make([]byte, len(merged4)*5)
	for i, r := range merged4 {
		binary.BigEndian.PutUint32(enc4[i*5:], r.from)
		enc4[i*5+4] = r.country
	}

	// IPv6: 17 bytes per entry [8B big-endian hi][8B big-endian lo][1B country_idx]
	enc6 := make([]byte, len(merged6)*17)
	for i, r := range merged6 {
		binary.BigEndian.PutUint64(enc6[i*17:], r.hi)
		binary.BigEndian.PutUint64(enc6[i*17+8:], r.lo)
		enc6[i*17+16] = r.country
	}

	b64v4 := base64.StdEncoding.EncodeToString(enc4)
	b64v6 := base64.StdEncoding.EncodeToString(enc6)

	fmt.Printf("IPv4 data: %d bytes -> %d base64 chars\n", len(enc4), len(b64v4))
	fmt.Printf("IPv6 data: %d bytes -> %d base64 chars\n", len(enc6), len(b64v6))

	// --- Write geodata.go ---
	out, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	fmt.Fprintf(out, "// Code generated by go generate; DO NOT EDIT.\n")
	fmt.Fprintf(out, "// Source: IP2Location LITE DB1 (20%02d-%02d-%02d)\n\n", dbYear, dbMonth, dbDay)
	fmt.Fprintf(out, "package traefik_country_block\n\n")

	// Country codes
	fmt.Fprintf(out, "var geoCountryCodes = []string{\n")
	for _, cc := range countryList {
		fmt.Fprintf(out, "\t%q,\n", cc)
	}
	fmt.Fprintf(out, "}\n\n")

	// IPv4 data as chunked base64
	writeBase64Const(out, "geoIPv4Data", b64v4)
	fmt.Fprintf(out, "\n")

	// IPv6 data as chunked base64
	writeBase64Const(out, "geoIPv6Data", b64v6)
	fmt.Fprintf(out, "\n")

	fmt.Printf("Written %s (%d country codes)\n", *output, len(countryList))
}

func writeBase64Const(f *os.File, name string, s string) {
	if s == "" {
		fmt.Fprintf(f, "const %s = \"\"\n", name)
		return
	}
	fmt.Fprintf(f, "const %s = \"\" +\n", name)
	const chunkSize = 76
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunk := s[i:end]
		if end < len(s) {
			fmt.Fprintf(f, "\t%q +\n", chunk)
		} else {
			fmt.Fprintf(f, "\t%q\n", chunk)
		}
	}
}
