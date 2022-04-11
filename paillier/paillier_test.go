package paillier

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(rand.Reader, 2048)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 128)
	require.NoError(t, err)

	t.Logf("%x", key.Lambda.Bytes())

	v := int64(58)

	t.Log("encrypt...")
	ct := key.Public.Encrypt(v)

	t.Log("decrypt...")
	v2 := key.Decrypt(ct)
	require.Equal(t, v, v2)
}

func TestPublicKey_Add(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	a := key.Public.Encrypt(10)
	b := key.Public.Encrypt(20)

	c := key.Public.Add(a, b)

	v := key.Decrypt(c)
	require.Equal(t, v, int64(30))
}
