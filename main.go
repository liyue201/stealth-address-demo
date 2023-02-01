package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

func main() {

	// 1.
	// Bob generates a key m, and computes M = G * m,
	// where G is a commonly-agreed generator point for the elliptic curve.
	// The stealth meta-address is an encoding of M.

	m, _ := new(big.Int).SetString("3b3b08bba24858f7ab8b302428379198e521359b19784a40aeb4daddf4ad911c", 16)
	Mx, My := secp256k1.S256().ScalarBaseMult(m.Bytes())
	M := secp256k1.CompressPubkey(Mx, My)

	fmt.Printf("m: %x\n", m.Bytes())
	fmt.Printf("M: %x\n", M)

	// 2.
	// Alice generates an ephemeral key r, and publishes the ephemeral public key R = G * r.

	r, _ := new(big.Int).SetString("9d23679323734fdf371017048b4a73cf160566a0ccd69fa087299888d9fbc59f", 16)
	Rx, Ry := secp256k1.S256().ScalarBaseMult(r.Bytes())
	R := secp256k1.CompressPubkey(Rx, Ry)

	fmt.Printf("r: %x\n", r.Bytes())
	fmt.Printf("R: %x\n", R)

	// 3.
	// Alice can compute a shared secret S = M * r, and Bob can compute the same shared secret S = m * R.

	Sx, Sy := secp256k1.S256().ScalarMult(Mx, My, r.Bytes())   // S = M * r
	S2x, S2y := secp256k1.S256().ScalarMult(Rx, Ry, m.Bytes()) // S = m * R

	S := secp256k1.CompressPubkey(Sx, Sy)
	S2 := secp256k1.CompressPubkey(S2x, S2y)

	fmt.Printf("S : %x\n", S)
	fmt.Printf("S2: %x\n", S2)
	if string(S) != string(S2) {
		panic("shared secret does not match")
	}

	// 4.
	// In general, in both Bitcoin and Ethereum (including correctly-designed ERC-4337 accounts),
	// an address is a hash containing the public key used to verify transactions from that address.
	// So you can compute the address if you compute the public key. To compute the public key,
	// Alice or Bob can compute P = M + G * hash(S)

	hashS := new(big.Int).Mod(new(big.Int).SetBytes(S), secp256k1.S256().N) //  hash(S)

	//fmt.Printf("hashS: %x\n", hashS.Bytes())

	GSx, GSy := secp256k1.S256().ScalarBaseMult(hashS.Bytes()) //  G * hash(S)
	Px, Py := secp256k1.S256().Add(Mx, My, GSx, GSy)           //  M + G * hash(S)

	P := secp256k1.CompressPubkey(Px, Py)
	fmt.Printf("P: %x\n", P)

	stealthAddress := crypto.PubkeyToAddress(ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     Px,
		Y:     Py,
	})
	fmt.Printf("A: %s\n", stealthAddress.String())

	// 5.
	// To compute the private key for that address, Bob (and Bob alone) can compute p = m + hash(S)
	p := new(big.Int).Add(m, hashS)             // p = m + hash(S)
	p = new(big.Int).Mod(p, secp256k1.S256().N) // p = p % N,  private key must be less than the order of the curve

	fmt.Printf("p: %x\n", p.Bytes())

	// 6.
	// private key to public key
	P2x, P2y := secp256k1.S256().ScalarBaseMult(p.Bytes())
	P2 := secp256k1.CompressPubkey(P2x, P2y)

	fmt.Printf("P2: %x\n", P2)
	if string(P) != string(P2) {
		panic("public key does not match")
	}
}
