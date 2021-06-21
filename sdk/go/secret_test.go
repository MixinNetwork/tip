package tip

import "testing"

func BenchmarkDeriveSecret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DeriveSecret("123456", "2e613adae4f0167255933a3ec1d97e0acdd38e46d319c348b7a3d709f23bae8f")
	}
}
