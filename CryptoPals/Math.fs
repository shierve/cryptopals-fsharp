module Crypto.Math

open System.Numerics

let modExp a b n =
    BigInteger.ModPow(a, b, n)


/// Returns a BigInteger random number from 0 (inclusive) to max (exclusive).
let randomBigInteger (max:bigint) =
    let rec getNumBytesInRange num bytes =
        if max < num then bytes
        else getNumBytesInRange (num * 256I) bytes+1
    let bytesNeeded = getNumBytesInRange 256I 1
    let bytes = Data.randomBytes (bytesNeeded+1)
    bytes.[bytesNeeded] <- 0uy
    (bigint bytes) % max