package paillier

import (
	"crypto/rand"
	"io"
	"math/big"
	rnd "math/rand"
	"time"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type PrivateKey struct {
	Lambda *big.Int
	Mu     *big.Int
	Public *PublicKey
}

type PublicKey struct {
	N  *big.Int
	G  *big.Int
	N2 *big.Int
}

func (pub *PublicKey) Encrypt(val int64) *big.Int {
	m := big.NewInt(val)

	if val < 0 || m.Cmp(zero) == -1 || m.Cmp(pub.N) != -1 {
		panic("invalid value")
	}

	// 计算r
	r := new(big.Int)
	gcd := new(big.Int)
	mathRand := rnd.New(rnd.NewSource(time.Now().UnixNano()))
	for {
		r.Rand(mathRand, pub.N)
		if gcd.GCD(nil, nil, r, pub.N).Cmp(one) == 0 {
			// fmt.Printf("r = %d\n", r.Int64())
			break
		}
	}

	// 加密运算
	r.Exp(r, pub.N, pub.N2)
	m.Exp(pub.G, m, pub.N2)

	c := new(big.Int).Mul(m, r)
	return c.Mod(c, pub.N2)
}

// Add 同态加法
func (pub *PublicKey) Add(a, b *big.Int) *big.Int {
	if a == nil || b == nil || a.Cmp(zero) != 1 || b.Cmp(zero) != 1 {
		panic("invalid input")
	}

	z := new(big.Int).Mul(a, b)
	return z.Mod(z, pub.N2)
}

// Decrypt 解密
func (k *PrivateKey) Decrypt(c *big.Int) int64 {
	if c == nil || c.Cmp(zero) != 1 {
		panic("invalid input")
	}

	m := L(new(big.Int).Exp(c, k.Lambda, k.Public.N2), k.Public.N)
	m.Mul(m, k.Mu)
	m.Mod(m, k.Public.N)
	return m.Int64()
}

func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

func GenerateKey(rd io.Reader, bits int) (*PrivateKey, error) {
	var (
		p, q, n, m *big.Int
		err        error
	)
	n, m = new(big.Int), new(big.Int)

	for {
		p, err = rand.Prime(rd, bits/2)
		if err != nil {
			return nil, err
		}
		q, err = rand.Prime(rd, bits/2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n.Mul(p, q)
		m.Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		// gcd(pq, (p-1)(q-1)) = 1
		if new(big.Int).GCD(nil, nil, n, m).Cmp(one) == 0 {
			break
		}
	}

	lambda := lcm(p.Sub(p, one), q.Sub(q, one))
	g := new(big.Int).Add(n, one)
	nn := new(big.Int).Mul(n, n)
	mu := new(big.Int).ModInverse(L(new(big.Int).Exp(g, lambda, nn), n), n)

	return &PrivateKey{
		Lambda: lambda,
		Mu:     mu,
		Public: &PublicKey{
			N:  n,
			G:  g,
			N2: nn,
		}}, nil
}

func lcm(a, b *big.Int) *big.Int {
	return new(big.Int).Div(
		new(big.Int).Mul(a, b),
		new(big.Int).GCD(nil, nil, a, b))
}
