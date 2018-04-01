module Crypto.Set2

open Crypto
open Crypto.Analysis
open System.IO


(****  SET 2  ****)

let ch9 () =
    let data = "YELLOW SUBMARINE" |> Data.fromString
    printfn "Before padding: %s" (Data.asHex data)
    printfn "Padded: %s" (Data.pad 20 data |> Data.asHex)

let ch10 () =
    let path = __SOURCE_DIRECTORY__ + "/../data/ch10.txt"
    let ciphertext = File.ReadAllLines path |> Array.reduce (+) |> Data.fromB64
    let key = Data.fromString "YELLOW SUBMARINE"
    let iv = Array.create 16 0uy
    let dec = Aes.decryptCBC key iv ciphertext
    printfn "Decrypted:\n\n%s" (Data.asString dec)

let ch11 () =
    let data = Array.create (16*4) 0uy
    let enigma = Encryption.encryptionOracle data
    let hasRepeatingBlock =
        enigma |> ( (Array.chunkBySize 16) >> (fun c -> Array.length (Array.distinct c) <> c.Length) )
    if hasRepeatingBlock then printfn "ECB"
    else printfn "CBC"

let ch12 () =
    let append =
        Data.fromB64 ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        + "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        + "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    let recoveredData = byteAtATime (Encryption.appendAndEncrypt append)
    // printfn "recovered data:\n\n%s" (Data.asString recoveredData)
    ()

let ch13 () =
    let data = "XXXXXX@XX.admin" + (Data.asString (Array.create 11 11uy)) + "XXX"
    let ciphertext = Server.profileFor data
    let blocks = Array.chunkBySize 16 ciphertext
    Data.asHex ciphertext |> printfn "%A"
    let forged = [|blocks.[0]; blocks.[3]; blocks.[2]; blocks.[1]|] |> Array.concat
    let userObject = Server.parseProfile forged
    printfn "forged user has role:\n\n%A" userObject.["role"]

let ch14 () =
    ch12() // Already implemented in challenge 12

let ch15 () =
    let m1 = Array.append (Data.fromString "ICE ICE BABY") (Array.create 4 4uy)
    let m2 = Array.append (Data.fromString "ICE ICE BABY") (Array.create 4 5uy)
    let m3 = Array.append (Data.fromString "ICE ICE BABY") [|1uy;2uy;3uy;4uy|]
    Data.removePadding m1 |> Data.asString |> printfn "padding removed: %A"
    try
        Data.removePadding m2 |> ignore
        ()
    with
    | Data.PaddingException -> printfn "padding exception"
    try
        Data.removePadding m3 |> ignore
        ()
    with
    | Data.PaddingException -> printfn "padding exception"

let ch16 () =
    let injectString = "XXXXXXXXXXXXXXXX:admin<true"
    let ciphertext = Server.encryptUserData injectString
    Server.checkAdmin ciphertext |> printfn "admin: %A"
    ciphertext.[32] <- ciphertext.[32] ^^^ 1uy
    ciphertext.[38] <- ciphertext.[38] ^^^ 1uy
    Server.checkAdmin ciphertext |> printfn "admin: %A"