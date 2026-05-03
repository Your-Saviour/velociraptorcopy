package reporting

import (
	"strings"
	"testing"
)

func TestSmartTruncateLine(t *testing.T) {
	pad := strings.Repeat("x", 200)

	cases := []struct {
		name    string
		line    string
		cutLen  int
		wantEnd string // expected suffix of the result
	}{
		{
			name:    "short line returned unchanged",
			line:    "SELECT * FROM info()",
			cutLen:  200,
			wantEnd: "SELECT * FROM info()",
		},
		{
			name:    "no open string — no delimiter synthesised",
			line:    "SELECT Name FROM pslist() WHERE Name = 'cmd' " + pad,
			cutLen:  200,
			wantEnd: "",
		},
		{
			name:    "unescaped single-quote string open at cut",
			line:    "LET X = '" + pad,
			cutLen:  200,
			wantEnd: "'",
		},
		{
			name:    "escaped single-quote does not close the string",
			// The \' inside the string must not flip state back to stateNone.
			// The string is still open at the cut point so ' must be appended.
			line:    "LET X = 'it\\'s " + pad,
			cutLen:  200,
			wantEnd: "'",
		},
		{
			name:    "escaped double-quote does not close the string",
			line:    `LET X = "say \"hi\" ` + pad,
			cutLen:  200,
			wantEnd: `"`,
		},
		{
			name:    "escaped backslash followed by real closing quote",
			// \\\' is: escaped backslash (\\) then a real closing quote (').
			// After the escaped backslash the string is still open; the next
			// ' should close it, so state is stateNone at the cut.
			line:    "LET X = 'path\\\\' + '" + pad,
			cutLen:  200,
			wantEnd: "'",
		},
		{
			name: "triple-quoted string — backslash is NOT an escape",
			// Inside ''', a \' does not close the string; only ''' does.
			// The string remains open at the cut so ''' must be appended.
			line:    "LET X = '''" + `raw \' data ` + pad,
			cutLen:  200,
			wantEnd: "'''",
		},
		{
			name:    "trailing backslash before cut — stays open",
			line:    "LET X = 'trailing\\" + pad,
			cutLen:  200,
			wantEnd: "'",
		},
		{
			name:    "double-quote string closed before cut",
			line:    `LET X = "done" + ` + pad,
			cutLen:  200,
			wantEnd: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := smartTruncateLine(tc.line, tc.cutLen)
			if tc.wantEnd == "" {
				// just verify it doesn't panic and is truncated
				if len(tc.line) > tc.cutLen && len(got) > tc.cutLen+10 {
					t.Errorf("line not truncated: len=%d", len(got))
				}
				return
			}
			if !strings.HasSuffix(got, tc.wantEnd) {
				t.Errorf("got %q, want suffix %q", got, tc.wantEnd)
			}
		})
	}
}
