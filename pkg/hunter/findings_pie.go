package hunter

// Filter will return a new slice containing only the elements that return
// true from the condition. The returned slice may contain zero elements (nil).
//
// FilterNot works in the opposite way of Filter.
func (ss Findings) Filter(condition func(Finding) bool) (ss2 Findings) {
	for _, s := range ss {
		if condition(s) {
			ss2 = append(ss2, s)
		}
	}
	return
}
