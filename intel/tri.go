package intel

// Tri is three-valued (Kleene) logic. UNKNOWN propagates instead of being
// silently turned into TRUE or FALSE.
type Tri int8

const (
	False   Tri = 0
	Unknown Tri = 1
	True    Tri = 2
)

func (t Tri) String() string {
	switch t {
	case True:
		return "true"
	case False:
		return "false"
	}
	return "unknown"
}

func (t Tri) Not() Tri {
	switch t {
	case True:
		return False
	case False:
		return True
	}
	return Unknown
}

// And of no operands is TRUE; Or of no operands is FALSE.
func triAnd(v []Tri) Tri {
	out := True
	for _, x := range v {
		if x == False {
			return False
		}
		if x == Unknown {
			out = Unknown
		}
	}
	return out
}

func triOr(v []Tri) Tri {
	out := False
	for _, x := range v {
		if x == True {
			return True
		}
		if x == Unknown {
			out = Unknown
		}
	}
	return out
}
