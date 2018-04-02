open Crypto
open System
open System.IO
open Crypto.Set1
open Crypto.Set2
open Crypto.Set3
open Crypto.Set4
open Crypto.PublicKey
open Crypto.Math
open Suave.Web
open Crypto.SuaveServer.UserController
open System.Net
open FSharp.Data
open FSharp.Data.HttpRequestHeaders


(****  SET 4  ****)

let p =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        + "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        + "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        + "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        + "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        + "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        + "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        + "fffffffffffff"
        |> Data.bigIntFromHex

let g = 2I

let ch33 () =
    let (a, A) = PublicKey.genDiffieHellmanKeyPair 37I 5I
    let (b, B) = PublicKey.genDiffieHellmanKeyPair 37I 5I
    let sa = PublicKey.genDiffieHellmanSessionKeys 37I a B
    let sb = PublicKey.genDiffieHellmanSessionKeys 37I b A
    sa |> (fun (k, mk) -> (Data.asHex k, Data.asHex mk)) |> printfn "a session keys: %A"
    sb |> (fun (k, mk) -> (Data.asHex k, Data.asHex mk)) |> printfn "b session keys: %A"
    // Now with big numbers
    let (aa, AA) = PublicKey.genDiffieHellmanKeyPair p g
    let (bb, BB) = PublicKey.genDiffieHellmanKeyPair p g
    let saa = PublicKey.genDiffieHellmanSessionKeys p aa BB
    let sbb = PublicKey.genDiffieHellmanSessionKeys p bb AA
    saa |> (fun (k, mk) -> (Data.asHex k, Data.asHex mk)) |> printfn "a session keys: %A"
    sbb |> (fun (k, mk) -> (Data.asHex k, Data.asHex mk)) |> printfn "b session keys: %A"
    p.ToByteArray() |> Array.rev |> Data.asHex |> printfn "p: %A"

let ch34 () =
    let (a, A) = PublicKey.genDiffieHellmanKeyPair p g
    let (b, B) = PublicKey.genDiffieHellmanKeyPair p g
    let sA = PublicKey.genDiffieHellmanSessionKey p a p // = sha1(0)
    let sB = PublicKey.genDiffieHellmanSessionKey p b p // = sha1(0)
    let sM = (0I).ToByteArray() |> Hash.sha1 |> (fun a -> a.[..15])
    let iv = Data.randomBytes 16
    let aMessage = Aes.encryptCBC sA iv (Data.pad 16 (Data.fromString "The quick brown fox jumps over the lazy dog"))
    let mReceived = Aes.decryptCBC sM iv aMessage
    let bReceived = Aes.decryptCBC sB iv aMessage
    let bMessage = Aes.encryptCBC sB iv (Data.tryRemovePadding bReceived)
    let mReceived2 = Aes.decryptCBC sM iv bMessage
    let aReceived = Aes.decryptCBC sA iv bMessage
    printfn "A sends: \"The quick brown fox jumps over the lazy dog\""
    Data.asString (Data.tryRemovePadding mReceived) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding bReceived) |> printfn "B receives %A"
    Data.asString (Data.tryRemovePadding mReceived2) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding aReceived) |> printfn "A receives %A"

let ch35 () =
    // When g = 1 then A = 1**a mod p = 1 -> [ s = 1**a mod p = 1 ]
    let (a, A) = PublicKey.genDiffieHellmanKeyPair p 1I
    let (b, B) = PublicKey.genDiffieHellmanKeyPair p 1I
    let sA = PublicKey.genDiffieHellmanSessionKey p a B // = sha1(1)
    let sB = PublicKey.genDiffieHellmanSessionKey p b A // = sha1(1)
    let sM = (1I).ToByteArray() |> Hash.sha1 |> (fun a -> a.[..15])
    let iv = Data.randomBytes 16
    let aMessage = Aes.encryptCBC sA iv (Data.pad 16 (Data.fromString "The quick brown fox jumps over the lazy dog"))
    let mReceived = Aes.decryptCBC sM iv aMessage
    let bReceived = Aes.decryptCBC sB iv aMessage
    let bMessage = Aes.encryptCBC sB iv (Data.tryRemovePadding bReceived)
    let mReceived2 = Aes.decryptCBC sM iv bMessage
    let aReceived = Aes.decryptCBC sA iv bMessage
    printfn "g = 1"
    Data.asString (Data.tryRemovePadding mReceived) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding bReceived) |> printfn "B receives %A"
    Data.asString (Data.tryRemovePadding mReceived2) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding aReceived) |> printfn "A receives %A"
    // When g = p then A = p**a mod p = 0 -> [ s = 0**a mod p = 0 ]
    let (a, A) = PublicKey.genDiffieHellmanKeyPair p p
    let (b, B) = PublicKey.genDiffieHellmanKeyPair p p
    let sA = PublicKey.genDiffieHellmanSessionKey p a B // = sha1(0)
    let sB = PublicKey.genDiffieHellmanSessionKey p b A // = sha1(0)
    let sM = (0I).ToByteArray() |> Hash.sha1 |> (fun a -> a.[..15])
    let iv = Data.randomBytes 16
    let aMessage = Aes.encryptCBC sA iv (Data.pad 16 (Data.fromString "The quick brown fox jumps over the lazy dog"))
    let mReceived = Aes.decryptCBC sM iv aMessage
    let bReceived = Aes.decryptCBC sB iv aMessage
    let bMessage = Aes.encryptCBC sB iv (Data.tryRemovePadding bReceived)
    let mReceived2 = Aes.decryptCBC sM iv bMessage
    let aReceived = Aes.decryptCBC sA iv bMessage
    printfn "g = p"
    Data.asString (Data.tryRemovePadding mReceived) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding bReceived) |> printfn "B receives %A"
    Data.asString (Data.tryRemovePadding mReceived2) |> printfn "M receives %A"
    Data.asString (Data.tryRemovePadding aReceived) |> printfn "A receives %A"
    // When g = p - 1
    // then A = (p-1)**a mod p = either 1 or p - 1  (depends if a is pair or odd)
    // and then s = either 1 or p - 1
    let (a, A) = PublicKey.genDiffieHellmanKeyPair p (p-1I)
    let (b, B) = PublicKey.genDiffieHellmanKeyPair p (p-1I)
    let sA = PublicKey.genDiffieHellmanSessionKey p a B // = sha1(1 or p-1)
    let sB = PublicKey.genDiffieHellmanSessionKey p b A // = sha1(1 or p-1)
    let sM1 = (1I).ToByteArray() |> Hash.sha1 |> (fun a -> a.[..15])
    let sM2 = (p-1I).ToByteArray() |> Hash.sha1 |> (fun a -> a.[..15])
    let iv = Data.randomBytes 16
    let aMessage = Aes.encryptCBC sA iv (Data.pad 16 (Data.fromString "The quick brown fox jumps over the lazy dog"))
    let mReceiveda = Aes.decryptCBC sM1 iv aMessage
    let mReceivedb = Aes.decryptCBC sM2 iv aMessage
    let bReceived = Aes.decryptCBC sB iv aMessage
    let bMessage = Aes.encryptCBC sB iv (Data.tryRemovePadding bReceived)
    let mReceived2a = Aes.decryptCBC sM1 iv bMessage
    let mReceived2b = Aes.decryptCBC sM2 iv bMessage
    let aReceived = Aes.decryptCBC sA iv bMessage
    printfn "g = p - 1"
    // We can guess the most provable correct guess with frequency evaluation,
    let mReceived =
        [mReceiveda; mReceivedb]
        |> List.map (fun d -> (d, Analysis.frequencyEvaluation d))
        |> List.minBy (fun (_, f) -> f)
        |> (fun (d, _) -> d)
    let mReceived2 =
        [mReceived2a; mReceived2b]
        |> List.map (fun d -> (d, Analysis.frequencyEvaluation d))
        |> List.minBy (fun (_, f) -> f)
        |> (fun (d, _) -> d)
    Data.asString (Data.tryRemovePadding mReceived) |> printfn "M guesses %A"
    Data.asString (Data.tryRemovePadding bReceived) |> printfn "B receives %A"
    Data.asString (Data.tryRemovePadding mReceived2) |> printfn "M guesses %A"
    Data.asString (Data.tryRemovePadding aReceived) |> printfn "A receives %A"

let ch36 () =
    let N = p
    let k = 3I
    let I = "Alice"
    let p = "password"
    printfn "> 0. Server generates salt and v"
    let salt = Data.randomBytes 8
    let xH = Array.concat [| salt; (Data.fromString I); (Data.fromString p) |] |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
    let v = modExp g xH N
    printfn "> 1. Alice sends username I and public ephemeral value A to the server"
    let (a, A) = genDiffieHellmanKeyPair N g
    printfn "> 2. Server sends salt s and public ephemeral value B to Alice"
    let b = randomBigInteger N
    let B = (k * v + (modExp g b N)) % N
    printfn "> 3. Alice and server calculate the random scrambling parameter"
    let u = Array.append (A.ToByteArray ()) (B.ToByteArray ()) |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
    printfn "> 4. Alice computes session key"
    let x = Array.concat [| salt; (Data.fromString I); (Data.fromString p) |] |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
    let aux = (k * (modExp g x N)) % N
    let s = modExp (modulo (B - aux) N) (a + u * x) N
    let key = Hash.sha256 (s.ToByteArray ())
    printfn "k: %A" (abs s)
    printfn "> 5. Server computes session key"
    let Ss = modExp (A * (modExp v u N)) b N
    let KeyS = Hash.sha256 (Ss.ToByteArray ())
    printfn "k: %A" Ss
    printfn "> 6. Alice sends proof of session key to server"
    let Mc = Hash.hmacsha256 key salt
    printfn "hmac: %A" (Data.asHex Mc)
    printfn "> 7. Server validates"
    let Ms = Hash.hmacsha256 KeyS salt
    printfn "hmac: %A" (Data.asHex Ms)

let ch37 () =
    let I = "alice"
    let N = p
    let p = "password"
    let k = 3I
    let resp1 = 
        Http.RequestString
            ( "http://127.0.0.1:8080/api/user/new", 
            headers = [ ContentType HttpContentTypes.Json ],
            body = TextRequest """ {"I": "alice", "p": "password"} """)
    printfn "%A" resp1
    // Proper Session
    printfn "1. Try Server with normal session"
    let (a, A) = genDiffieHellmanKeyPair N g
    let resp2 = 
        Http.RequestString
            ( "http://127.0.0.1:8080/api/user/newsession",
            headers = [ ContentType HttpContentTypes.Json ],
            body = TextRequest (" {\"I\": \"alice\", \"A\": \"" + (Data.bigIntAsHex A) +  "\" }"))
    let jsonResp = JsonValue.Parse(resp2)
    let Bjson = jsonResp.GetProperty "b"
    let Sjson = jsonResp.GetProperty "salt"
    let B = Bjson.AsString() |> Data.bigIntFromHex
    let salt = Sjson.AsString() |> Data.fromHex
    let u = Array.append (A.ToByteArray ()) (B.ToByteArray ()) |> Hash.sha256 |> Data.toBigInt
    // Session Key
    let x = Array.concat [| salt; (Data.fromString I); (Data.fromString p) |] |> Hash.sha256 |> Data.toBigInt
    let aux = (k * (modExp g x N)) % N
    let s = modExp (modulo (B - aux) N) (a + u * x) N
    let key = Hash.sha256 (s.ToByteArray ())
    printfn "key: %A" (Data.asHex key)
    let hmacKey = Hash.hmacsha256 key salt
    let resp = 
        Http.RequestString
            ( "http://127.0.0.1:8080/api/user/validatesession",
            headers = [ ContentType HttpContentTypes.Json ],
            body = TextRequest (" {\"I\": \"alice\", \"k\": \"" + (Data.asHex hmacKey) +  "\" }"))
    printfn "%A" resp

    // zero key
    printfn "2. Zero key session"
    let resp2 = 
        Http.RequestString
            ( "http://127.0.0.1:8080/api/user/newsession",
            headers = [ ContentType HttpContentTypes.Json ],
            body = TextRequest (" {\"I\": \"alice\", \"A\": \"" + "0000" +  "\" }"))
    let jsonResp = JsonValue.Parse(resp2)
    let Sjson = jsonResp.GetProperty "salt"
    let salt = Sjson.AsString() |> Data.fromHex
    let s = 0I
    let key = Hash.sha256 (s.ToByteArray ())
    printfn "key: %A" (Data.asHex key)
    let hmacKey = Hash.hmacsha256 key salt
    let resp = 
        Http.RequestString
            ( "http://127.0.0.1:8080/api/user/validatesession",
            headers = [ ContentType HttpContentTypes.Json ],
            body = TextRequest (" {\"I\": \"alice\", \"k\": \"" + (Data.asHex hmacKey) +  "\" }"))
    printfn "%A" resp

let ch38 () =
    let N = p
    let k = 3I
    let I = "Alice"
    let p = "password"
    printfn "> 0. MITM forges arbitrary salt and v"
    let salt = Data.randomBytes 8
    let xH = Array.concat [| salt; (Data.fromString p) |] |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
    let v = modExp g xH N
    printfn "> 1. Alice sends username I and public ephemeral value A to the server"
    let (a, A) = genDiffieHellmanKeyPair N g
    printfn "> 2. MITM sends salt s, u and public ephemeral value B to Alice"
    let b = 1I
    let B = modExp g b N
    let u = Data.randomBytes 16 |> Data.toBigInt
    printfn "> 3. Alice computes session key"
    let x = Array.concat [| salt; (Data.fromString p) |] |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
    let s = modExp B (a + u * x) N
    let key = Hash.sha256 (s.ToByteArray ())
    printfn "k: %A" (Data.asHex key)
    printfn "> 4. MITM performs dictionary attack"
    let dictionaryPath = "/usr/share/dict/cracklib-small"
    let dictionary = File.ReadAllLines dictionaryPath
    printfn "dictionary size: %A" dictionary.Length
    let mutable found = false
    let findPassword words =
        words
        |>  Array.tryFind (fun f ->
            if not found then
                printfn "%A" f
                let xf = Array.concat [| salt; (Data.fromString f) |] |> Hash.sha256 |> Data.asHex |> Data.bigIntFromHex
                let sf = modulo (A * (modExp g (u * xf) N)) N
                let kf = Hash.sha256 (sf.ToByteArray ())
                if kf = key then
                    found <- true
                    true
                else
                    false
            else
                false
        )
    let partDictionary = Array.splitInto 4 dictionary
    let foundPassword = Array.Parallel.choose findPassword partDictionary
    printfn "found password: %A" foundPassword.[0]
    
let ch39 () =
    let (pubK, privK) = genRSAKeyPair 8 3
    let c = RSAEncrypt pubK (new bigint 42)
    let p = RSADecrypt privK c
    printfn "decrypted: %A" p
    let (pubK', privK') = genRSAKeyPair 1024 3
    let m = "the quick brown fox jumps over the lazy dog" |> Data.fromString |> Data.toBigInt
    let c' = RSAEncrypt pubK' m
    let p' = RSADecrypt privK' c'
    let pm = p'.ToByteArray () |> Array.rev |> Data.asString
    printfn "decrypted: %A" pm

[<EntryPoint>]
let main argv =
    let challenges: (unit -> unit)[] =
        [|
            ch1; ch2; ch3; ch4; ch5; ch6; ch7; ch8;  // SET 1
            ch9; ch10; ch11; ch12; ch13; ch14; ch15; ch16;  // SET 2
            ch17; ch18; ch19; ch20; ch21; ch22; ch23; ch24;  // SET 3
            ch25; ch26; ch27; ch28; ch29; ch30; ch31; ch32;  // SET 4
            ch33; ch34; ch35; ch36; ch37; ch38; ch39; // SET 5
        |]
    if argv.Length > 0 then
        if (int argv.[0]) = -1 then
            startWebServer defaultConfig (UserController Crypto.SuaveServer.UserDB.UserDB)
        else
            let challenge: (unit -> unit) = challenges.[(int argv.[0])-1]
            challenge ()
    else
        let challenge: (unit -> unit) = challenges.[challenges.Length-1]
        challenge ()
    0 // return an integer exit code
