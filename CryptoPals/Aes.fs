module Crypto.Aes

open System.Security.Cryptography
open System


let blockSize = 16

let encrypt (block: byte[]) key =
    if (block.Length <> blockSize)
    then raise (System.ArgumentException("Block must be of blockSize bytes"))
    else
        use aes = new AesManaged()
        aes.Mode <- CipherMode.ECB
        aes.Key <- key
        aes.Padding <- PaddingMode.None
        let encryptor = aes.CreateEncryptor(aes.Key, aes.IV)
        let output = Array.create blockSize 0uy
        encryptor.TransformBlock(block, 0, blockSize, output, 0) |> ignore
        output

let decrypt (block: byte[]) key =
    if (block.Length <> blockSize)
    then raise (System.ArgumentException("Block must be of blockSize bytes"))
    else
        use aes = new AesManaged()
        aes.Mode <- CipherMode.ECB
        aes.Key <- key
        aes.Padding <- PaddingMode.None
        let decryptor = aes.CreateDecryptor(aes.Key, aes.IV)
        let output = Array.create blockSize 0uy
        decryptor.TransformBlock(block, 0, blockSize, output, 0) |> ignore
        output

let encryptECB (plain: byte[]) (key: byte[]): byte[] =
    let padded = Data.pad blockSize plain
    [|
        for block in padded |> Array.chunkBySize blockSize do
            yield! encrypt (block) key
    |]

let decryptECB (cipher: byte[]) (key: byte[]): byte[] =
    [|
        for block in cipher |> Array.chunkBySize blockSize do
            yield! decrypt (block) key
    |]

let encryptCBC (key: byte[]) (iv: byte[]) (plain: byte[]): byte[] =
    let padded = Data.pad blockSize plain
    let mutable last = iv
    [|
        for block in padded |> Array.chunkBySize blockSize do
            last <- encrypt (Data.xor block last) key
            yield! last
    |]

let decryptCBC (key: byte[]) (iv: byte[]) (cipher: byte[]): byte[] =
    [|
        let blocks = Array.chunkBySize blockSize cipher
        for (i, block) in (Array.indexed blocks) do
            let lastCipher =
                if i = 0 then iv
                else blocks.[i-1]
            yield! Data.xor (decrypt (block) key) lastCipher
    |]