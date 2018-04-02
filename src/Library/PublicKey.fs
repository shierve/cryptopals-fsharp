module Crypto.PublicKey

open System.Numerics
open Crypto.Math
open Crypto
open Crypto

let genDiffieHellmanKeyPair (p: BigInteger) (g: BigInteger) =
    let a = randomBigInteger p
    let A = modExp g a p
    (a, A)

let genDiffieHellmanSessionKeys (p: BigInteger) (secret: BigInteger) (pub: BigInteger) =
    let s = modExp pub secret p
    let keyPair = s.ToByteArray() |> Hash.sha256 |> Array.chunkBySize 16
    (keyPair.[0], keyPair.[1]) // (Key, MacKey)

let genDiffieHellmanSessionKey (p: BigInteger) (secret: BigInteger) (pub: BigInteger) =
    let s = modExp pub secret p
    let key = s.ToByteArray() |> Hash.sha1
    key.[..15]

type RSAPubKey = {
    e: int;
    n: bigint;
}

type RSAPrivKey = {
    d: bigint;
    n: bigint;
}

let genRSAKeyPair (bits: int) (e: int): (RSAPubKey * RSAPrivKey) =
    let rnd = System.Random()
    let p = nextPrimePredicate rnd (bits/2) 30 (fun x -> (gcd (x-1I) (new bigint(e))) = 1I)
    let q = nextPrimePredicate rnd (bits/2) 30 (fun x -> (gcd (x-1I) (new bigint(e))) = 1I && x <> p)
    let n = p * q
    let et = (p - 1I) * (q - 1I)
    let d = invMod (new bigint(e)) et
    ({e = e; n = n}, {d = d; n = n}) // public | private
    
let RSAEncrypt (pubK: RSAPubKey) (m: bigint) =
    modExp m (new bigint(pubK.e)) pubK.n
    
let RSADecrypt (privK: RSAPrivKey) (c: bigint) =
    modExp c privK.d privK.n