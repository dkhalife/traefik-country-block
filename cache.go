package traefik_country_block

import "sync"

type cache struct {
	m sync.Map
}

func newCache() *cache {
	return &cache{}
}

func (c *cache) get(ip string) (allowed bool, found bool) {
	val, ok := c.m.Load(ip)
	if !ok {
		return false, false
	}
	return val.(bool), true
}

func (c *cache) set(ip string, allowed bool) {
	c.m.Store(ip, allowed)
}
