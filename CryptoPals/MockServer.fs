module Crypto.Server

open System
open Crypto

let randomKey =
    let arr = Array.create 16 0uy
    let rnd = System.Random()
    rnd.NextBytes(arr)
    arr

let profileFor (email: string): byte[] =
    let sanitized = String.filter (fun c -> (c <> '&') && (c <> '=')) email
    Aes.encryptECB (Data.fromString ("email=" + sanitized + "&uid=10&role=user")) randomKey

let parseProfile (encryptedProfile: byte[]): Map<string, string> =
    let profile = Aes.decryptECB encryptedProfile randomKey |> Data.removePadding |> Data.asString
    let pairs =
        profile.Split('&')
        |> Array.map ( (fun (field: string) -> field.Split('='))
            >> (fun kv -> (kv.[0], kv.[1])) )
    Map.ofArray pairs

let encryptUserData (message: string) =
    "comment1=cooking%20MCs;userdata="
    + (String.filter (fun c -> c <> ';' && c <> '=') message)
    + ";comment2=%20like%20a%20pound%20of%20bacon"
    |> Data.fromString
    |> Aes.encryptCBC randomKey (Data.shiftLeft randomKey 0uy)

let checkAdmin (cipher: byte[]) =
    let userString =
        cipher
        |> Aes.decryptCBC randomKey (Data.shiftLeft randomKey 0uy)
        |> Data.removePadding
        |> Data.asString
    userString.Contains ";admin=true;"
