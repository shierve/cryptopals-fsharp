open System.IO
open Crypto
open Crypto.RNG
open Crypto.Utils
open System
open Crypto.Set1
open Crypto.Set2
open Crypto.Set3
open Crypto.Set4
open System.Security.Cryptography.X509Certificates
open Crypto


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
    let (a, A) = PublicKey.genDiffieHellmanKeyPair 37I 5I
    let (b, B) = PublicKey.genDiffieHellmanKeyPair 37I 5I
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



[<EntryPoint>]
let main argv =
    let challenges: (unit -> unit)[] =
        [|
            ch1; ch2; ch3; ch4; ch5; ch6; ch7; ch8;  // SET 1
            ch9; ch10; ch11; ch12; ch13; ch14; ch15; ch16;  // SET 2
            ch17; ch18; ch19; ch20; ch21; ch22; ch23; ch24;  // SET 3
            ch25; ch26; ch27; ch28; ch29; ch30; ch31; ch32;  // SET 4
            ch33; ch34;  // SET 5
        |]
    if argv.Length > 0 then
        let challenge: (unit -> unit) = challenges.[(int argv.[0])-1]
        challenge ()
    else
        let challenge: (unit -> unit) = challenges.[challenges.Length-1]
        challenge ()
    0 // return an integer exit code
