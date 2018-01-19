open System.IO
open Crypto
open Crypto.Analysis
open Crypto.RNG
open Crypto.Utils
open System
open System.Net
open FSharp.Data.JsonExtensions


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
    let ciphertext = Data.fromHex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    let candidates: (byte * byte[])[] =
        List.map ( fun k -> (byte k, (Data.singleByteXor ciphertext (byte k))) ) [0 .. 255] |> List.toArray
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
    Encryption.repeatingKeyXor (Data.fromString str) "ICE"
    |> (Data.asHex >> printfn "%s")

let ch6 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch6.txt"
    let ciphertext =
        File.ReadAllLines path
        |> Array.reduce (+)
        |> Data.fromB64
    let keySize = (bestKeySizes ciphertext).[0]
    printfn "Key Size chosen: %A" keySize
    let key =
        partitionAndTranspose ciphertext keySize
        |> Array.choose tryBestKey
        |> Array.map (fun (k, _, _) -> k)
        |> Data.asString
    printfn "Key found: %A" key
    Encryption.repeatingKeyXor ciphertext key |> Data.asString |> printfn "Decrypted Text:\n\n%s"

let ch7 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch7.txt"
    let ciphertext = File.ReadAllLines path |> Array.reduce (+) |> Data.fromB64
    let key = "YELLOW SUBMARINE" |> Data.fromString
    let plain = Aes.decryptECB ciphertext key
    printfn "Decrypted text:\n\n%s" (Data.asString plain)

let ch8 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch8.txt"
    let ciphertexts = File.ReadAllLines path |> Array.map Data.fromHex
    let maybeRepeatingBlock =
        ciphertexts
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


(****  SET 3  ****)

let ch17 () =
    let plain =
        Encryption.encryptRandomString ()
        |> Analysis.paddingOracleAttack Encryption.paddingOracle
    plain |> Data.removePadding |> Data.asString |> printfn "%s"

let ch18 () =
    let ciphertext = Data.fromB64 "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    let key = Data.fromString "YELLOW SUBMARINE"
    let nonce = Data.fromInt 0 |> Array.append (Array.create 4 0uy)
    let plain = Aes.CTR key nonce ciphertext
    printfn "%s" (plain |> Data.asString)

let ch19 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch19.txt"
    let key = Data.fromString "YELLOW SUBMARINE"
    let nonce = Data.fromInt 6138071 |> Array.append (Array.create 4 0uy)
    let ciphertexts =
        File.ReadAllLines path
        |> Array.map (Data.fromB64 >> (Aes.CTR key nonce))
    let maxLength = Array.maxBy (fun (arr: byte[]) -> arr.Length) ciphertexts |> Array.length
    let groupedBytes = [
        for i = 0 to (maxLength - 1) do
            yield Array.choose (fun (ciphertext: byte[]) ->
                if ciphertext.Length > i then
                    Some (ciphertext.[i])
                else
                    None
            ) ciphertexts
    ]
    let mutable key =
        groupedBytes
        |> List.choose tryBestKey
        |> List.map (fun (k, _, _) -> k)
        |> Array.ofList
    let testKey () =
        ciphertexts
        |> Array.map ((fun ciphertext -> Data.xor ciphertext key)
            >> Data.asString
            >> printfn "%s"
        ) |> ignore
    testKey ()
    printfn "\n> Input a position and a byte to change the byte in that position, q to quit."
    let mutable input: string[] = (Console.ReadLine()).Split ' '
    while input.[0] <> "q" do
        key.[int input.[0]] <- (byte input.[1])
        testKey ()
        printfn "\n> Input a position and a byte to change the byte in that position, q to quit."
        input <- (Console.ReadLine()).Split ' '

let ch20 () =
    // same as 19, but with higher success
    let path = __SOURCE_DIRECTORY__ + "/data/ch20.txt"
    let key = Data.fromString "YELLOW SUBMARINE"
    let nonce = Data.fromInt 518071 |> Array.append (Array.create 4 0uy)
    let ciphertexts =
        File.ReadAllLines path
        |> Array.map (Data.fromB64 >> (Aes.CTR key nonce))
    let maxLength = Array.maxBy (fun (arr: byte[]) -> arr.Length) ciphertexts |> Array.length
    let groupedBytes = [
        for i = 0 to (maxLength - 1) do
            yield Array.choose (fun (ciphertext: byte[]) ->
                if ciphertext.Length > i then
                    Some (ciphertext.[i])
                else
                    None
            ) ciphertexts
    ]
    let key =
        groupedBytes
        |> List.choose tryBestKey
        |> List.map (fun (k, _, _) -> k)
        |> Array.ofList
    ciphertexts
    |> Array.map ((fun ciphertext -> Data.xor ciphertext key)
        >> Data.asString
        >> printfn "%s"
    ) |> ignore

let ch21 () =
    let rng = MT19937()
    rng.Init 1131464071u
    for _i = 0 to 100 do
        printfn "%A" (rng.RandInt32())

let ch22 () =
    let rng = MT19937()
    let timestamp = unixTimestamp()
    printfn "Start timestamp: %A" timestamp
    let seconds1 = Random().Next(40,1000)
    let seconds2 = Random().Next(40,1000)
    let mutable output = 0
    let wait =
        async {
           do! Async.Sleep(seconds1 * 1000)
           let ts = unixTimestamp()
           printfn "Target timestamp: %A" ts
           rng.Seed ts
           do! Async.Sleep(seconds2 * 1000)
           output <- rng.RandInt ()
        }
    [ wait ]
    |> Async.Parallel
    |> Async.RunSynchronously
    |> ignore
    printfn "Start search"
    let mutable ts = unixTimestamp()
    rng.Seed ts
    let mutable forged = rng.RandInt ()
    while forged <> output do
        ts <- ts - 1
        rng.Seed ts
        forged <- rng.RandInt ()
    printfn "Found timestamp: %A" ts

let ch23 () =
    let rng = MT19937()
    rng.Seed (unixTimestamp())
    rng.Init 123u
    let mtclone = Array.create 624 0u
    for i = 0 to 623 do
        let output = rng.RandInt32()
        if i = 0 then printfn "sd? %A" output
        mtclone.[i] <- mt19937Untamper output
    let clone = MT19937()
    clone.State { mt = mtclone; mti = 0}
    for _i = 0 to 100 do
        rng.RandInt() |> abs |> printfn "original: %A"
        clone.RandInt() |> abs |> printfn "clone: %A"

let ch24 () =
    let astring = "AAAAAAAAAAAAAA" |> Data.fromString
    let seed = uint16 (unixTimestamp ())
    let ciphertext = Encryption.mt19937Prepend seed astring
    let noPrep = ciphertext.[(ciphertext.Length-14)..]
    let prepSize = ciphertext.Length-14
    let foundSeed =
        [ for i = 0 to (pown 2 16)-1 do yield uint16 i ]
        |> List.find (fun s ->
            let m = Array.append (Array.create prepSize 0uy) astring
            let t = Encryption.mt19937Cipher (int s) m
            let np = t.[(t.Length-14)..]
            np = noPrep
        )
    printfn "found seed: %A" foundSeed
    let timeseeded = Encryption.mt19937Cipher (unixTimestamp ()) astring
    let ts = unixTimestamp ()
    let maybeSeed =
        [ for i = 0 to (pown 2 16)-1 do yield i ]
        |> List.tryFind (fun i ->
            let ts2 = ts - i
            let t = Encryption.mt19937Cipher ts2 astring
            t = timeseeded
        )
    match maybeSeed with
    | Some s -> printfn "is time seeded with seed %A" (ts-s)
    | None -> printfn "not time seeded"


(****  SET 4  ****)

let ch25 () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch25.txt"
    let ct = File.ReadAllLines path |> Array.reduce (+) |> Data.fromB64
    let key = Data.fromString "YELLOW SUBMARINE"
    let plain = Aes.decryptECB ct key |> Data.tryRemovePadding
    let unknownKey = Data.randomBytes 16
    let nonce = Data.randomBytes 8
    let ciphertext = Aes.CTR unknownKey nonce plain
    let foundPlain =
        Array.mapi (fun i _ ->
            Array.concat [|
                [| for i = 96uy to 127uy do yield i |];
                [| for i = 64uy to 95uy do yield i |];
                [| 8uy; 9uy; 10uy |];
                [| for i = 32uy to 63uy do yield i |] |]
            |> Array.tryFind (fun testByte ->
                let newCiphertext = Aes.editCTR unknownKey nonce ciphertext [| testByte |] i
                newCiphertext = ciphertext
            )
        ) ciphertext
        |>  Array.map (fun opt ->
                match opt with
                | Some l -> l
                | None -> 63uy // '?'
            )
        |> Data.asString
    printfn "found plaintext:\n\n%s" foundPlain


let ch26 () =
    let injectString = ":admin<true"
    let ciphertext = Server.encryptUserDataCTR injectString
    Server.checkAdminCTR ciphertext |> printfn "admin: %A"
    ciphertext.[32] <- ciphertext.[32] ^^^ 1uy
    ciphertext.[38] <- ciphertext.[38] ^^^ 1uy
    Server.checkAdminCTR ciphertext |> printfn "admin: %A"

let ch27 () =
    let injectString = "XXXXXXXXXXXX"
    let ciphertext = Server.encryptUserDataIVeqK injectString
    let blocks = Array.chunkBySize 16 ciphertext
    try
        Server.validatePlainCBC (Array.concat [| blocks.[0]; (Array.create 16 0uy) ; blocks.[0] |])
    with
        | Server.InvalidAsciiException plain ->
            let blocks2 = plain |> Array.chunkBySize 16
            let foundIV = Data.xor blocks2.[0] blocks2.[2]
            printfn "original iv/key: %A" (Data.asHex Server.randomKey)
            printfn "found iv/key: %A" (Data.asHex foundIV)

let ch28 () =
    let key = Data.fromString "The quick "
    let message = Data.fromString "brown fox jumps over the lazy dog"
    let hash = Hash.sha1mac key message
    Data.asHex hash |> printfn "hex: %A"
    Data.asB64 hash |> printfn "b64: %A"

let ch29 () =
    let message = Data.fromString "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    let rnd = System.Random()
    let keySize = rnd.Next(10, 20)
    let key = Data.randomBytes keySize
    printfn "key size: %A" keySize
    let mac = Hash.sha1mac key message
    printfn "mac: %A" (Data.asHex mac)
    // registers (h0-4)
    let registers =
        Array.chunkBySize 4 mac
        |> Array.map (Array.rev >> (fun bts -> BitConverter.ToUInt32(bts, 0)))
    let newMessage = Data.fromString ";admin=true"
    // 1024 limit keySize
    let mm = uint64 (1024 + (newMessage.Length * 8))
    let newMac = Hash.sha1Append newMessage registers mm
    printfn "new mac: %A" (Data.asHex newMac)
    // Try different key lengths to forge sha1(message | glue padding | new)
    let keySize =
        [ for i = 0 to 100 do yield i ]
        |> List.tryFind (fun ks ->
            let forgedMessage = Array.concat [| message; (Hash.sha1GluePadding ks message.Length); newMessage |]
            let comp = Hash.sha1mac key forgedMessage
            comp = newMac
        )
    match keySize with
    | None -> printfn "key size not found"
    | Some ks ->
        printfn "key size found: %A" ks
        (Array.concat [| message; (Hash.sha1GluePadding ks message.Length); newMessage |])
        |> Data.asString
        |> printfn "forged message: %A"

let ch30 () =
    let message = Data.fromString "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    let rnd = System.Random()
    let keySize = rnd.Next(10, 20)
    let key = Data.randomBytes keySize
    printfn "key size: %A" keySize
    let mac = Hash.md4mac key message
    printfn "mac: %A" (Data.asHex mac)
    // registers (h0-4)
    let registers =
        Array.chunkBySize 4 mac
        |> Array.map (fun bts -> BitConverter.ToUInt32(bts, 0))
    let newMessage = Data.fromString ";admin=true"
    // 1024 limit keySize
    let mm = uint64 (1024 + (newMessage.Length * 8))
    let newMac = Hash.md4Append newMessage registers mm
    printfn "new mac: %A" (Data.asHex newMac)
    // Try different key lengths to forge md4(message | glue padding | new)
    let keySize =
        [ for i = 0 to 100 do yield i ]
        |> List.tryFind (fun ks ->
            let forgedMessage = Array.concat [| message; (Hash.md4GluePadding ks message.Length); newMessage |]
            let comp = Hash.md4mac key forgedMessage
            comp = newMac
        )
    match keySize with
    | None -> printfn "key size not found"
    | Some ks ->
        printfn "key size found: %A" ks
        (Array.concat [| message; (Hash.md4GluePadding ks message.Length); newMessage |])
        |> Data.asString
        |> printfn "forged message: %A"

let ch31 () =
    let k = Data.fromString "key"
    let m = Data.fromString "The quick brown fox jumps over the lazy dog"
    let hmac = Hash.hmacsha1 k m
    printfn "hmac: %A" (Data.asHex hmac)
    try
        let a =
            fetchJson "http://localhost:3000/ch31?file=hello&signature=fb1954b0164e4d9fd3c0bc7ac1ff3c029d4e9012"
        printfn "response: %A" a
    with
        | _ -> printfn "Server not started"
    printfn "fb1954b0164e4d9fd3c0bc7ac1ff3c029d4e9012"
    let foundSignature = Analysis.timingLeak "http://localhost:3000/ch31" "hello"
    printfn "found: %A" (Data.asHex foundSignature)


[<EntryPoint>]
let main argv =
    let challenges: (unit -> unit)[] =
        [|
            ch1; ch2; ch3; ch4; ch5; ch6; ch7; ch8;  // SET 1
            ch9; ch10; ch11; ch12; ch13; ch14; ch15; ch16;  // SET 2
            ch17; ch18; ch19; ch20; ch21; ch22; ch23; ch24;  // SET 3
            ch25; ch26; ch27; ch28; ch29; ch30; ch31;  // SET 4
        |]
    if argv.Length > 0 then
        let challenge: (unit -> unit) = challenges.[(int argv.[0])-1]
        challenge ()
    else
        let challenge: (unit -> unit) = challenges.[challenges.Length-1]
        challenge ()
    0 // return an integer exit code
