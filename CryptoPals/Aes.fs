module Crypto.Aes

open System.Security.Cryptography
open System


let blockSize = 16

let encrypt (block: byte[]) key =
    if (Array.length block <> blockSize)
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
    if (Array.length block <> blockSize)
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
    [|
        for block in plain |> Array.chunkBySize blockSize do
            yield! encrypt (block) key
    |]

let decryptECB (cipher: byte[]) (key: byte[]): byte[] =
    [|
        for block in cipher |> Array.chunkBySize blockSize do
            yield! decrypt (block) key
    |]