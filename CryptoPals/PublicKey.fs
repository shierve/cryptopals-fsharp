module Crypto.PublicKey

open System.Numerics
open Crypto.Math
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
