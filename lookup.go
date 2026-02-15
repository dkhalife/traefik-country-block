package traefik_country_block

import (
	"fmt"

	ip2location "github.com/ip2location/ip2location-go/v9"
)

type lookup struct {
	db *ip2location.DB
}

func newLookup(dbPath string) (*lookup, error) {
	db, err := ip2location.OpenDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open IP2Location database at %q: %w", dbPath, err)
	}
	return &lookup{db: db}, nil
}

func (l *lookup) country(ip string) (string, error) {
	record, err := l.db.Get_country_short(ip)
	if err != nil {
		return "", fmt.Errorf("country lookup failed for %q: %w", ip, err)
	}
	return record.Country_short, nil
}

func (l *lookup) close() {
	l.db.Close()
}
