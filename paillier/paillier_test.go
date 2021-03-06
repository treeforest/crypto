package paillier

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
	"time"
)

func BenchmarkGenerateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKey(rand.Reader, 2048)
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 10)
	require.NoError(t, err)

	t.Logf("%x", key.Lambda.Bytes())

	v := int64(25)

	t.Log("encrypt...")
	ct := key.Public.Encrypt(v)
	t.Logf("密文：%d", ct.Int64())

	t.Log("decrypt...")
	v2 := key.Decrypt(ct)
	require.Equal(t, v, v2)
}

func TestPublicKey_Add(t *testing.T) {
	key, err := GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	a := key.Public.Encrypt(10)
	time.Sleep(time.Nanosecond)
	b := key.Public.Encrypt(20)
	time.Sleep(time.Nanosecond)
	t.Logf("a=%d", a.Int64())
	t.Logf("b=%d", b.Int64())

	c := key.Public.Add(a, b)
	t.Logf("c=%d", c.Int64())

	d := key.Public.Encrypt(30)
	t.Logf("d=%d", d.Int64())
	require.Equal(t, key.Decrypt(c), key.Decrypt(d))

	v := key.Decrypt(c)
	require.Equal(t, v, int64(30))
}

func Test(t *testing.T) {
	g := big.NewInt(47)
	n := big.NewInt(30)
	var d, x, y big.Int
	d.GCD(&x, &y, g, n)
	t.Logf("x = %d, y = %d", x.Int64(), y.Int64())

	if x.Sign() == -1 {
		t.Logf("z = %d", new(big.Int).Add(&x, n).Int64())
	} else {
		t.Logf("z = %d", x.Int64())
	}

	c := new(big.Int).ModInverse(g, n)
	t.Logf("c = %d", c.Int64())
}
