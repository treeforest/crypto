package rsa

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var (
	one = big.NewInt(1)
)

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
	N *big.Int
}

func (pub *PublicKey) Size() int {
	return pub.N.BitLen() / 8
}

func (pub *PublicKey) Encrypt(msg []byte) ([]byte, error) {
	if msg == nil || len(msg) == 0 {
		return nil, errors.New("message error")
	}

	m := new(big.Int).SetBytes(msg)
	if len(msg) > pub.Size() || m.Cmp(pub.N) != -1 {
		// 要求 msg 的长度小于 N 的长度，且 m 得小于 N
		return nil, fmt.Errorf("message too long, it should be less than %d", pub.Size())
	}

	c := new(big.Int).Exp(m, pub.E, pub.N)
	return c.Bytes(), nil
}

func (pub *PublicKey) Verify(sign []byte, hash []byte) bool {
	c := new(big.Int).SetBytes(sign)
	h := new(big.Int).Exp(c, pub.E, pub.N)
	if bytes.Equal(h.Bytes(), hash) {
		return true
	}
	return false
}

func (key *PrivateKey) Decrypt(msg []byte) []byte {
	c := new(big.Int).SetBytes(msg)
	m := new(big.Int).Exp(c, key.D, key.N)
	return m.Bytes()
}

func (key *PrivateKey) Sign(hash []byte) []byte {
	sign := new(big.Int).Exp(new(big.Int).SetBytes(hash), key.D, key.N)
	return sign.Bytes()
}

func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	p, err := rand.Prime(random, bits)
	if err != nil {
		return nil, err
	}
	q, err := rand.Prime(random, bits)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).Mul(p, q)
	fn := new(big.Int).Mul(p.Sub(p, one), q.Sub(q, one))

	e := big.NewInt(65537) // 默认初始值
	for {
		// e和fn得互为质数
		if new(big.Int).GCD(nil, nil, e, fn).Cmp(one) == 0 {
			break
		}

		e, err = rand.Prime(random, 6) // 避免位数过大
		if err != nil {
			return nil, err
		}
	}

	d := new(big.Int).ModInverse(e, fn)

	return &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: e,
		},
		N: n,
		D: d,
	}, nil
}
