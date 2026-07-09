//go:build !go1.25

package self_test

import "github.com/metacubex/jls-tls"

func getCurveID(connState tls.ConnectionState) tls.CurveID {
	return 0
}
