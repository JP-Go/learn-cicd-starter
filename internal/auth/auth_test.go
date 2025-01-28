package auth

import (
	"net/http"
	"testing"
)

type testcase struct {
	name     string
	input    string
	expected string
	err      error
}

func Test_Errors_With_No_AuthHeader(t *testing.T) {
	cases := []testcase{
		{
			name:     "No headers",
			expected: "",
		},
		{
			name:     "Empty auth header",
			input:    "",
			expected: "",
		},
	}

	for i, c := range cases {
		header := http.Header{}
		header.Add("Authorization", c.input)
		out, err := GetAPIKey(header)
		cases[i].err = err
		if err == nil || out != c.expected {
			t.Errorf("case %v. expected %s, got %s. expected error %v, got %v",
				c.name,
				c.expected,
				out,
				ErrNoAuthHeaderIncluded,
				err,
			)
		}
	}
}

func Test_Errors_With_AuthHeader_Malformed_Or_Wrong_Protocol(t *testing.T) {
	tests := map[string][]testcase{
		"malformed": {{
			name:     "Malformed (no spaces)",
			input:    "Bearer:Malformed",
			expected: "",
		}, {
			name:     "Malformed (no spaces, dash)",
			input:    "Bearer-Malformed",
			expected: "",
		}, {
			name:     "Malformed (too many spaces)",
			input:    "Bearer  Malformed",
			expected: "",
		}, {
			name:     "Malformed (no second part)",
			input:    "Bearer ",
			expected: "",
		}}, "wrong protocol": {{
			name:     "WellFormed (Wrong protocol) 1",
			input:    "Bearer Well-Formed",
			expected: "",
		}, {
			name:     "WellFormed (Wrong protocol) 2",
			input:    "Basic dXNlcm5hbWU6cGFzc3dvcmQK",
			expected: "",
		}},
	}

	for name, cases := range tests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				input := http.Header{}
				input.Add("Authorization", c.input)
				out, err := GetAPIKey(input)
				if err == nil || out != c.expected {
					t.Errorf("case %v. expected %s, got %s. expected any error, got %v",
						c.name,
						c.expected,
						out,
						err,
					)
				}

			}
		})
	}
}

func Test_Success_With_AuthHeader_Wellformed(t *testing.T) {
	tests := map[string][]testcase{
		"wellformed": {{
			name:     "Wellformed (any string)",
			input:    "ApiKey GoodApiKey",
			expected: "GoodApiKey",
		}, {
			name:     "WellFormed (hash)",
			input:    "ApiKey cdeb1050d144ff339ab5320b768b308e",
			expected: "cdeb1050d144ff339ab5320b768b308e",
		},
		}}

	for name, cases := range tests {
		t.Run(name, func(t *testing.T) {
			for _, c := range cases {
				input := http.Header{}
				input.Add("Authorization", c.input)
				out, err := GetAPIKey(input)
				if err != nil || out != c.expected {
					t.Errorf("case %v. expected %s, got %s. expected no error, got %v",
						c.name,
						c.expected,
						out,
						err,
					)
				}
			}
		})
	}
}
