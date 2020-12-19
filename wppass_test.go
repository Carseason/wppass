package wppass

import "testing"

func TestVerfiyPass(t *testing.T) {
	state := VerfiyPass("admin123", "$P$B12345678.8beAbNGrptg9h4PwkOt9.")
	t.Log(state)
	t.Fail()
}

func TestHashPass(t *testing.T) {
	if pass, err := HashPass("12345678", "admin123"); err != nil {
		t.Error(err)
	} else {
		t.Log(pass)
	}
	t.Fail()
}
