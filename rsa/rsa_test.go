package rsa

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(rand.Reader, 512)
	}
}

func Test_Encrypt_Decrypt(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	v := []byte("hello world")
	c, err := key.PublicKey.Encrypt(v)
	require.NoError(t, err)

	m := key.Decrypt(c)
	require.Equal(t, v, m)
}

func Test_Sign_Verify(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	msg := []byte("hello world")
	hash := sha256.Sum256(msg)

	sign := key.Sign(hash[:])
	ok := key.PublicKey.Verify(sign, hash[:])
	require.Equal(t, true, ok)
}
