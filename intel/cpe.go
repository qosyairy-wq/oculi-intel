// Package intel is OCULI's software vulnerability intelligence engine:
// software identity resolution, the signed offline intelligence snapshot,
// and CVE applicability evaluation. It has no Windows dependencies so the
// endpoint app and the snapshot builder share exactly the same logic.
package intel

import (
	"fmt"
	"strings"
)

// CPE is a parsed CPE 2.3 formatted string. Values are unescaped and lower-cased.
// "*" means ANY and "-" means NA, exactly as in the CPE 2.3 naming specification.
type CPE struct {
	Part, Vendor, Product, Version, Update, Edition, Language string
	SwEdition, TargetSW, TargetHW, Other                      string
}

// ParseCPE parses "cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other".
func ParseCPE(s string) (CPE, error) {
	if len(s) > 512 {
		return CPE{}, fmt.Errorf("CPE too long")
	}
	fields := splitCPE(s)
	if len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return CPE{}, fmt.Errorf("not a CPE 2.3 formatted string")
	}
	for i := range fields {
		fields[i] = strings.ToLower(unescapeCPE(fields[i]))
	}
	c := CPE{Part: fields[2], Vendor: fields[3], Product: fields[4], Version: fields[5], Update: fields[6], Edition: fields[7],
		Language: fields[8], SwEdition: fields[9], TargetSW: fields[10], TargetHW: fields[11], Other: fields[12]}
	if c.Part != "a" && c.Part != "o" && c.Part != "h" {
		return CPE{}, fmt.Errorf("invalid CPE part %q", c.Part)
	}
	if c.Vendor == "" || c.Product == "" || c.Vendor == "*" || c.Product == "*" {
		return CPE{}, fmt.Errorf("CPE without vendor/product")
	}
	return c, nil
}

// Key is the identity key used by the snapshot index: part:vendor:product.
func (c CPE) Key() string { return c.Part + ":" + c.Vendor + ":" + c.Product }

// ProductKey builds an index key from components.
func ProductKey(part, vendor, product string) string {
	return strings.ToLower(part + ":" + vendor + ":" + product)
}

func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune('\\')
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	out = append(out, cur.String())
	return out
}

func unescapeCPE(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	esc := false
	for _, r := range s {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// anyValue reports whether a CPE attribute places no constraint.
func anyValue(v string) bool { return v == "*" || v == "" }
