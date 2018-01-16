module Crypto.Encryption

open System.Text
open Crypto
open System.IO
open Crypto.RNG

let randomKey =
    let arr = Array.create 16 0uy
    let rnd = System.Random()
    rnd.NextBytes(arr)
    arr

let repeatingKeyXor (data: byte[]) (key: string): byte[] =
    let length = Array.length data
    let times = length/(String.length key)
    let last = length%(String.length key)
    let repeatString = (String.replicate times key) + key.[..(last-1)]
    let repeatingKey = Encoding.ASCII.GetBytes repeatString
    Data.xor data repeatingKey

let encryptionOracle (data: byte[]): byte[] =
    let rnd = System.Random()
    let prependSize = rnd.Next(5, 11)
    let prepend = Array.create prependSize 0uy
    rnd.NextBytes(prepend)
    let appended = Array.append prepend data |> Data.pad 16
    let mode = rnd.Next(2)
    let key = Array.create 16 0uy
    let iv = Array.create 16 0uy
    rnd.NextBytes(key)
    rnd.NextBytes(iv)
    if mode = 0 then Aes.encryptECB appended key
    else Aes.encryptCBC key iv appended

let appendAndEncrypt (append: byte[]) data =
    let rnd = System.Random(int randomKey.[0])
    let prepSize = rnd.Next(50)
    let prep = Array.create prepSize 0uy
    rnd.NextBytes(prep)
    let appended = Array.concat [|prep; data; append|]
    Aes.encryptECB appended randomKey

let encryptRandomString () =
    let path = __SOURCE_DIRECTORY__ + "/data/ch17.txt"
    let dataList = File.ReadAllLines path |> Array.map (Data.fromB64 >> Data.pad 16)
    let iv = Array.create 16 0uy
    let rnd = System.Random()
    rnd.NextBytes(iv)
    let choice = rnd.Next(dataList.Length)
    let cipher = Aes.encryptCBC randomKey iv dataList.[choice]
    (iv, cipher)

let paddingOracle (iv: byte[], cipher: byte[]): bool =
    let plain = Aes.decryptCBC randomKey iv cipher
    try
        Data.removePadding plain |> ignore
        true
    with
    | Data.PaddingException -> false

let mt19937Cipher (data: byte[]) (seed: int): byte[] =
    let rng = MT19937()
    rng.Seed seed
    data
    |> Array.map (fun b -> b ^^^ (byte (rng.RandInt32())) )
