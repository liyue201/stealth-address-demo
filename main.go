package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

func EncodePoint(x, y *big.Int) *big.Int {
	temp := new(big.Int).Set(x)
	temp.Lsh(temp, 256)
	temp.Add(temp, y)
	return temp
}

func DecodePoint(p *big.Int) (*big.Int, *big.Int) {
	temp := new(big.Int).Lsh(big.NewInt(1), 256)
	x, y := new(big.Int).DivMod(p, temp, new(big.Int))
	return x, y
}

func HashPointToField(x, y *big.Int) *big.Int {
	temp := EncodePoint(x, y)
	return new(big.Int).Mod(temp, secp256k1.S256().N)
}

func main() {

	// 1.
	// Bob generates a key m, and computes M = G * m,
	// where G is a commonly-agreed generator point for the elliptic curve.
	// The stealth meta-address is an encoding of M.

	m, _ := new(big.Int).SetString("3b3b08bba24858f7ab8b302428379198e521359b19784a40aeb4daddf4ad911c", 16)

	fmt.Printf("m: %x\n", m.Bytes())

	Mx, My := secp256k1.S256().ScalarBaseMult(m.Bytes())

	fmt.Printf("M: (%x, %x)\n", Mx.Bytes(), My.Bytes())

	stealthMetaAddress := EncodePoint(Mx, My)

	fmt.Printf("stealth meta-address : %x\n", stealthMetaAddress.Bytes())

	// 2.
	// Alice generates an ephemeral key r, and publishes the ephemeral public key R = G * r.

	r, _ := new(big.Int).SetString("9d23679323734fdf371017048b4a73cf160566a0ccd69fa087299888d9fbc59f", 16)

	fmt.Printf("r: %x\n", r.Bytes())

	Rx, Ry := secp256k1.S256().ScalarBaseMult(r.Bytes())

	fmt.Printf("R: (%x, %x)\n", Rx.Bytes(), Ry.Bytes())

	// 3.
	// Alice can compute a shared secret S = M * r, and Bob can compute the same shared secret S = m * R.

	Sx, Sy := secp256k1.S256().ScalarMult(Mx, My, r.Bytes())
	S2x, S2y := secp256k1.S256().ScalarMult(Rx, Ry, m.Bytes())

	fmt.Printf("S: (%x, %x)\n", Sx.Bytes(), Sy.Bytes())
	fmt.Printf("S2: (%x, %x)\n", S2x.Bytes(), S2y.Bytes())

	// 4.
	// In general, in both Bitcoin and Ethereum (including correctly-designed ERC-4337 accounts),
	// an address is a hash containing the public key used to verify transactions from that address.
	// So you can compute the address if you compute the public key. To compute the public key,
	// Alice or Bob can compute P = M + G * hash(S)

	hashS := HashPointToField(Sx, Sy)                          //  hash(S)
	GSx, GSy := secp256k1.S256().ScalarBaseMult(hashS.Bytes()) //  G * hash(S)
	Px, Py := secp256k1.S256().Add(Mx, My, GSx, GSy)           //  M + G * hash(S)

	fmt.Printf("P: (%x, %x)\n", Px.Bytes(), Py.Bytes())

	stealthAddress := crypto.PubkeyToAddress(ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     Px,
		Y:     Py,
	})
	fmt.Printf("stealth address: %s\n", stealthAddress.String())

	// 5.
	// To compute the private key for that address, Bob (and Bob alone) can compute p = m + hash(S)
	p := new(big.Int).Add(m, hashS)

	fmt.Printf("p: %x\n", p.Bytes())

	//6.
	// private key to public key
	publicKeyX, publicKeyY := secp256k1.S256().ScalarBaseMult(p.Bytes())

	fmt.Printf("public key: (%x, %x)\n", publicKeyX.Bytes(), publicKeyY.Bytes())

	if Px.Cmp(publicKeyX) != 0 || Py.Cmp(publicKeyY) != 0 {
		panic("public key does not match")
	}
}
