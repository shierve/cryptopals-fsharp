module Crypto.Set4

open Crypto
open Crypto.Utils
open System.IO
open System


(****  SET 4  ****)

let ch25 () =
    let path = __SOURCE_DIRECTORY__ + "/../data/ch25.txt"
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
    let foundSignature = Analysis.timingLeak "http://localhost:3000/ch31" "hello" 60
    match foundSignature with
    | Some s ->
        printfn "found: %A" (Data.asHex s)
    | None ->
        printfn "Signature not found"

let ch32 () =
    // Same as ch31. Works with 3ms delay
    try
        fetchJson "http://localhost:3000/ch31?file=hello&signature=fb1954b0164e4d9fd3c0bc7ac1ff3c029d4e9012" |> ignore
        printfn "server Ok"
    with
        | _ -> printfn "Server not started"
    printfn "fb1954b0164e4d9fd3c0bc7ac1ff3c029d4e9012"
    let foundSignature = Analysis.timingLeak "http://localhost:3000/ch31" "hello" 60
    match foundSignature with
    | Some s ->
        printfn "found: %A" (Data.asHex s)
    | None ->
        printfn "Signature not found"