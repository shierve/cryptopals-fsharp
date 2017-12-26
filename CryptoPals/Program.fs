open System.IO
open Crypto
open Crypto.Analysis
open Crypto.Encryption


(****  SET 1  ****)

let ch1 () =
    let ch1String = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let d = Data.fromHex ch1String
    Data.asB64 d |> printfn "%s"

let ch2 () =
    let d1 = Data.fromHex "1c0111001f010100061a024b53535009181c"
    let d2 = Data.fromHex "686974207468652062756c6c277320657965"
    let xord = Data.xor d1 d2
    Data.asHex xord |> printfn "%s"

let ch3 () =
    let cipher = Data.fromHex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    let candidates: (byte * byte[])[] = List.map ( fun k -> (byte k, (Data.singleByteXor cipher (byte k))) ) [0 .. 255] |> List.toArray
    let sortedCandidates = frequencySort candidates
    printfn "There are %A valid candidates:" (Array.length sortedCandidates)
    Array.iter (fun (k, d, s) -> printfn "[key: %A] %A (Score: %A)" k (Data.asString d) s) sortedCandidates

let ch4 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch4.txt"
    let bestKeys =
        File.ReadAllLines path
        |> Array.choose (Data.fromHex >> tryBestKey)
        |> Array.mapi (fun i (k, d, s) -> (i, k, d, s))
        |> Array.sortBy (fun (_, _, _, s) -> s)
    Array.iter (fun (i, k, d, s) -> printfn "[line: %A][key: %A][score: %A] %A" i k s (Data.asString d)) bestKeys

let ch5 () =
    let str = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    repeatingKeyXor (Data.fromString str) "ICE"
    |> (Data.asHex >> printfn "%s")

let ch6 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch6.txt"
    let cipher =
        File.ReadAllLines path
        |> Array.reduce (+)
        |> Data.fromB64
    let keySize = (bestKeySizes cipher).[0]
    printfn "Key Size chosen: %A" keySize
    let key =
        partitionAndTranspose cipher keySize
        |> Array.choose tryBestKey
        |> Array.map (fun (k, _, _) -> k)
        |> Data.asString
    printfn "Key found: %A" key
    repeatingKeyXor cipher key |> Data.asString |> printfn "Decrypted Text:\n\n%s"

let ch7 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch7.txt"
    let cipher = File.ReadAllLines path |> Array.reduce (+) |> Data.fromB64
    let key = "YELLOW SUBMARINE" |> Data.fromString
    let plain = Aes.decryptECB cipher key
    printfn "Decrypted text:\n\n%s" (Data.asString plain)

let ch8 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch8.txt"
    let ciphers = File.ReadAllLines path |> Array.map Data.fromHex
    let maybeRepeatingBlock =
        ciphers
        |> Array.tryFindIndex
            ( (Array.chunkBySize 16) >> (fun c -> Array.length (Array.distinct c) <> c.Length) )
    match maybeRepeatingBlock with
    | Some index -> printfn "Repeating block found at line %A" (index+1)
    | None -> printfn "No repeating blocks found"


(****  SET 2  ****)

let ch9 () =
    let data = "YELLOW SUBMARINE" |> Data.fromString
    printfn "Before padding: %s" (Data.asHex data)
    printfn "Padded: %s" (Data.pad 20 data |> Data.asHex)

let ch10 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch10.txt"
    let cipher = File.ReadAllLines path |> Array.reduce (+) |> Data.fromB64
    let key = Data.fromString "YELLOW SUBMARINE"
    let iv = Array.create 16 0uy
    let dec = Aes.decryptCBC key iv cipher
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
    let cipher = Server.profileFor data
    let blocks = Array.chunkBySize 16 cipher
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
    | Data.PaddingException msg -> printfn "padding exception: %A" msg
    try
        Data.removePadding m3 |> ignore
        ()
    with
    | Data.PaddingException msg -> printfn "padding exception: %A" msg

let ch16 () =
    let injectString = "XXXXXXXXXXXXXXXX:admin<true"
    let cipher = Server.encryptUserData injectString
    Server.checkAdmin cipher |> printfn "admin: %A"
    cipher.[32] <- cipher.[32] ^^^ 1uy
    cipher.[38] <- cipher.[38] ^^^ 1uy
    Server.checkAdmin cipher |> printfn "admin: %A"


[<EntryPoint>]
let main argv =
    let challenges: (unit -> unit)[] =
        [|ch1;ch2;ch3;ch4;ch5;ch6;ch7;ch8;ch9;ch10;ch11;ch12;ch13;ch14;ch15;ch16|]
    let challenge: (unit -> unit) = challenges.[(int argv.[0])-1]
    challenge () |> ignore
    0 // return an integer exit code
