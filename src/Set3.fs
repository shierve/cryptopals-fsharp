module Crypto.Set3

open Crypto
open Crypto.Analysis
open Crypto.Utils
open Crypto.RNG
open System.IO
open System


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
    let path = __SOURCE_DIRECTORY__ + "/../data/ch19.txt"
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
    let path = __SOURCE_DIRECTORY__ + "/../data/ch20.txt"
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