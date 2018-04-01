module Crypto.Server

open System
open Crypto

let randomKey =
    Data.randomBytes 16
let randomIV =
    Data.randomBytes 16
let randomNonce =
    Data.randomBytes 8

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
    |> Data.pad 16
    |> Aes.encryptCBC randomKey randomIV

let checkAdmin (cipher: byte[]) =
    let userString =
        cipher
        |> Aes.decryptCBC randomKey randomIV
        |> Data.removePadding
        |> Data.asString
    userString.Contains ";admin=true;"

let encryptUserDataCTR (message: string) =
    "comment1=cooking%20MCs;userdata="
    + (String.filter (fun c -> c <> ';' && c <> '=') message)
    + ";comment2=%20like%20a%20pound%20of%20bacon"
    |> Data.fromString
    |> Data.pad 16
    |> Aes.CTR randomKey randomNonce

let checkAdminCTR (cipher: byte[]) =
    let userString =
        cipher
        |> Aes.CTR randomKey randomNonce
        |> Data.removePadding
        |> Data.asString
    userString.Contains ";admin=true;"

let encryptUserDataIVeqK (message: string) =
    "comment1=cooking%20MCs;userdata="
    + (String.filter (fun c -> c <> ';' && c <> '=') message)
    + ";comment2=%20like%20a%20pound%20of%20bacon"
    |> Data.fromString
    |> Data.pad 16
    |> Aes.encryptCBC randomKey randomKey

exception InvalidAsciiException of byte[]

let validatePlainCBC (ciphertext: byte[]) =
    let plain =
        Aes.decryptCBC randomKey randomKey ciphertext
        |> Data.tryRemovePadding
    if Array.exists (fun b -> b > 127uy) plain then
        raise (InvalidAsciiException (plain))
    else
        ()