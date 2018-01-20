module Crypto.Hash

open System.Security.Cryptography
open System
open Crypto


let rec leftrotate (n: uint32) (r: int): uint32 =
    if r = 1 then
        if n >>> 31 <> 0ul then
            ((n <<< 1) + 1ul)
        else
            (n <<< 1)
    else
        let mutable n' = n
        for _i = 0 to (r-1) do
            n' <- leftrotate n' 1
        n'


let sha1 (data: byte[]) =
    let mutable h0: uint32 = 0x67452301ul
    let mutable h1: uint32 = 0xEFCDAB89ul
    let mutable h2: uint32 = 0x98BADCFEul
    let mutable h3: uint32 = 0x10325476ul
    let mutable h4: uint32 = 0xC3D2E1F0ul
    let ml: uint64 = (uint64 data.Length) * 8UL

    // pre-processing
    let mutable message: byte[] = data
    message <- Array.append message [| 0x80uy |]
    while (message.Length * 8) % 512 <> 448 do
        message <- Array.append message [| 0x00uy |]
    let p = (BitConverter.GetBytes ml) |> Array.rev
    message <- Array.append message p

    // process
    Array.chunkBySize 64 message
    |>  Array.iter ( fun (block: byte[]) ->
            // 32-bit words
            let w: uint32[] =
                Array.append (
                    Array.chunkBySize 4 block
                    |> Array.map (fun (bts: byte[]) -> BitConverter.ToUInt32((Array.rev bts), 0))
                ) (Array.create 64 0ul)
            for i = 16 to 79 do
                w.[i] <- leftrotate (w.[i-3] ^^^ w.[i-8] ^^^ w.[i-14] ^^^ w.[i-16]) 1
            let mutable a = h0
            let mutable b = h1
            let mutable c = h2
            let mutable d = h3
            let mutable e = h4

            // main loop
            for i = 0 to 79 do
                let (f, k) =
                    if (0 <= i && i <= 19) then (
                            (b &&& c) ||| ((b ^^^ 0xFFFFFFFFul) &&& d),
                            0x5A827999ul
                        )
                    else if 20 <= i && i <= 39 then (
                            (b ^^^ c) ^^^ d,
                            0x6ED9EBA1ul
                        )
                    else if 40 <= i && i <= 59 then (
                            (b &&& c) ||| (b &&& d) ||| (c &&& d),
                            0x8F1BBCDCul
                        )
                    else (
                            (b ^^^ c) ^^^ d,
                            0xCA62C1D6ul
                        )
                let temp = (leftrotate a 5) + f + e + k + w.[i]
                e <- d
                d <- c
                c <- leftrotate b 30
                b <- a
                a <- temp
            h0 <- h0 + a;
            h1 <- h1 + b;
            h2 <- h2 + c;
            h3 <- h3 + d;
            h4 <- h4 + e;
        )
    // hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
    Array.concat [|
        (BitConverter.GetBytes h0) |> Array.rev;
        (BitConverter.GetBytes h1) |> Array.rev;
        (BitConverter.GetBytes h2) |> Array.rev;
        (BitConverter.GetBytes h3) |> Array.rev;
        (BitConverter.GetBytes h4) |> Array.rev;
    |]


let sha1Append (data: byte[]) (registers: uint32[]) (ml: uint64) =
    let mutable h0: uint32 = registers.[0]
    let mutable h1: uint32 = registers.[1]
    let mutable h2: uint32 = registers.[2]
    let mutable h3: uint32 = registers.[3]
    let mutable h4: uint32 = registers.[4]

    // pre-processing
    let mutable message: byte[] = data
    message <- Array.append message [| 0x80uy |]
    while (message.Length * 8) % 512 <> 448 do
        message <- Array.append message [| 0x00uy |]
    let p = (BitConverter.GetBytes ml) |> Array.rev
    message <- Array.append message p

    // process
    Array.chunkBySize 64 message
    |>  Array.iter ( fun (block: byte[]) ->
            // 32-bit words
            let w: uint32[] =
                Array.append (
                    Array.chunkBySize 4 block
                    |> Array.map (fun (bts: byte[]) -> BitConverter.ToUInt32((Array.rev bts), 0))
                ) (Array.create 64 0ul)
            for i = 16 to 79 do
                w.[i] <- leftrotate (w.[i-3] ^^^ w.[i-8] ^^^ w.[i-14] ^^^ w.[i-16]) 1
            let mutable a = h0
            let mutable b = h1
            let mutable c = h2
            let mutable d = h3
            let mutable e = h4

            // main loop
            for i = 0 to 79 do
                let (f, k) =
                    if (0 <= i && i <= 19) then (
                            (b &&& c) ||| ((b ^^^ 0xFFFFFFFFul) &&& d),
                            0x5A827999ul
                        )
                    else if 20 <= i && i <= 39 then (
                            (b ^^^ c) ^^^ d,
                            0x6ED9EBA1ul
                        )
                    else if 40 <= i && i <= 59 then (
                            (b &&& c) ||| (b &&& d) ||| (c &&& d),
                            0x8F1BBCDCul
                        )
                    else (
                            (b ^^^ c) ^^^ d,
                            0xCA62C1D6ul
                        )
                let temp = (leftrotate a 5) + f + e + k + w.[i]
                e <- d
                d <- c
                c <- leftrotate b 30
                b <- a
                a <- temp
            h0 <- h0 + a;
            h1 <- h1 + b;
            h2 <- h2 + c;
            h3 <- h3 + d;
            h4 <- h4 + e;
        )
    // hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
    Array.concat [|
        (BitConverter.GetBytes h0) |> Array.rev;
        (BitConverter.GetBytes h1) |> Array.rev;
        (BitConverter.GetBytes h2) |> Array.rev;
        (BitConverter.GetBytes h3) |> Array.rev;
        (BitConverter.GetBytes h4) |> Array.rev;
    |]

let sha1mac (key: byte[]) (message: byte[]) = Array.append key message |> sha1

let sha1GluePadding keySize messageLength =
    let mutable padding = [| 0x80uy |]
    while ((padding.Length + messageLength + keySize) * 8) % 512 <> 448 do
        padding <- Array.append padding [| 0x00uy |]
    let ml: uint64 = uint64 ((keySize + messageLength) * 8)
    let p = (BitConverter.GetBytes ml) |> Array.rev
    Array.append padding p


let md4GluePadding keySize messageLength =
    let mutable padding = [| 0x80uy |]
    while ((padding.Length + messageLength + keySize) * 8) % 512 <> 448 do
        padding <- Array.append padding [| 0x00uy |]
    let ml: uint64 = uint64 ((keySize + messageLength) * 8)
    let p = (BitConverter.GetBytes ml)
    Array.append padding p

let md4f x y z = (x &&& y) ||| ((~~~x) &&& z)

let md4g x y z = (x &&& y) ||| (x &&& z) ||| (y &&& z)

let md4h x y z = x ^^^ y ^^^ z

let md4op1 a b c d xk s = leftrotate (a + (md4f b c d) + xk) s

let md4op2 a b c d xk s = leftrotate(a + (md4g b c d) + xk + 0x5A827999ul) s

let md4op3 a b c d xk s = leftrotate(a + (md4h b c d) + xk + 0x6ED9EBA1ul) s


let md4 (data: byte[]) =
    (*
     * From the md4 description in:
     * www.faqs.org/rfcs/rfc1320.html
     *)
    let mutable a: uint32 = 0x67452301ul
    let mutable b: uint32 = 0xefcdab89ul
    let mutable c: uint32 = 0x98badcfeul
    let mutable d: uint32 = 0x10325476ul
    let size: uint64 = (uint64 data.Length) * 8UL

    // pre-processing
    let mutable message: byte[] = data
    message <- Array.append message [| 0x80uy |]
    while (message.Length * 8) % 512 <> 448 do
        message <- Array.append message [| 0x00uy |]
    let p = (BitConverter.GetBytes size)
    message <- Array.append message p

    // process
    Array.chunkBySize 64 message
    |>  Array.iter ( fun (block: byte[]) ->
            let X: uint32[] =
                Array.chunkBySize 4 block
                |> Array.map (fun (bts: byte[]) -> BitConverter.ToUInt32(bts, 0))
            
            let aa = a
            let bb = b
            let cc = c
            let dd = d

            // ROUND 1
            a <- md4op1 a b c d X.[0] 3
            d <- md4op1 d a b c X.[1] 7
            c <- md4op1 c d a b X.[2] 11
            b <- md4op1 b c d a X.[3] 19
            a <- md4op1 a b c d X.[4] 3
            d <- md4op1 d a b c X.[5] 7
            c <- md4op1 c d a b X.[6] 11
            b <- md4op1 b c d a X.[7] 19
            a <- md4op1 a b c d X.[8] 3
            d <- md4op1 d a b c X.[9] 7
            c <- md4op1 c d a b X.[10] 11
            b <- md4op1 b c d a X.[11] 19
            a <- md4op1 a b c d X.[12] 3
            d <- md4op1 d a b c X.[13] 7
            c <- md4op1 c d a b X.[14] 11
            b <- md4op1 b c d a X.[15] 19
            // ROUND 2
            a <- md4op2 a b c d X.[0] 3
            d <- md4op2 d a b c X.[4] 5
            c <- md4op2 c d a b X.[8] 9
            b <- md4op2 b c d a X.[12] 13
            a <- md4op2 a b c d X.[1] 3
            d <- md4op2 d a b c X.[5] 5
            c <- md4op2 c d a b X.[9] 9
            b <- md4op2 b c d a X.[13] 13
            a <- md4op2 a b c d X.[2] 3
            d <- md4op2 d a b c X.[6] 5
            c <- md4op2 c d a b X.[10] 9
            b <- md4op2 b c d a X.[14] 13
            a <- md4op2 a b c d X.[3] 3
            d <- md4op2 d a b c X.[7] 5
            c <- md4op2 c d a b X.[11] 9
            b <- md4op2 b c d a X.[15] 13
            // ROUND 3
            a <- md4op3 a b c d X.[0] 3
            d <- md4op3 d a b c X.[8] 9
            c <- md4op3 c d a b X.[4] 11
            b <- md4op3 b c d a X.[12] 15
            a <- md4op3 a b c d X.[2] 3
            d <- md4op3 d a b c X.[10] 9
            c <- md4op3 c d a b X.[6] 11
            b <- md4op3 b c d a X.[14] 15
            a <- md4op3 a b c d X.[1] 3
            d <- md4op3 d a b c X.[9] 9
            c <- md4op3 c d a b X.[5] 11
            b <- md4op3 b c d a X.[13] 15
            a <- md4op3 a b c d X.[3] 3
            d <- md4op3 d a b c X.[11] 9
            c <- md4op3 c d a b X.[7] 11
            b <- md4op3 b c d a X.[15] 15
            
            a <- a + aa
            b <- b + bb
            c <- c + cc
            d <- d + dd
        )
    // hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
    Array.concat [|
        (BitConverter.GetBytes a);
        (BitConverter.GetBytes b);
        (BitConverter.GetBytes c);
        (BitConverter.GetBytes d);
    |]

let md4Append (data: byte[]) (registers: uint32[]) (size: uint64) =
    (*
     * From the md4 description in:
     * www.faqs.org/rfcs/rfc1320.html
     *)
    let mutable a: uint32 = registers.[0]
    let mutable b: uint32 = registers.[1]
    let mutable c: uint32 = registers.[2]
    let mutable d: uint32 = registers.[3]

    // pre-processing
    let mutable message: byte[] = data
    message <- Array.append message [| 0x80uy |]
    while (message.Length * 8) % 512 <> 448 do
        message <- Array.append message [| 0x00uy |]
    let p = (BitConverter.GetBytes size)
    message <- Array.append message p

    // process
    Array.chunkBySize 64 message
    |>  Array.iter ( fun (block: byte[]) ->
            let X: uint32[] =
                Array.chunkBySize 4 block
                |> Array.map (fun (bts: byte[]) -> BitConverter.ToUInt32(bts, 0))
            
            let aa = a
            let bb = b
            let cc = c
            let dd = d

            // ROUND 1
            a <- md4op1 a b c d X.[0] 3
            d <- md4op1 d a b c X.[1] 7
            c <- md4op1 c d a b X.[2] 11
            b <- md4op1 b c d a X.[3] 19
            a <- md4op1 a b c d X.[4] 3
            d <- md4op1 d a b c X.[5] 7
            c <- md4op1 c d a b X.[6] 11
            b <- md4op1 b c d a X.[7] 19
            a <- md4op1 a b c d X.[8] 3
            d <- md4op1 d a b c X.[9] 7
            c <- md4op1 c d a b X.[10] 11
            b <- md4op1 b c d a X.[11] 19
            a <- md4op1 a b c d X.[12] 3
            d <- md4op1 d a b c X.[13] 7
            c <- md4op1 c d a b X.[14] 11
            b <- md4op1 b c d a X.[15] 19
            // ROUND 2
            a <- md4op2 a b c d X.[0] 3
            d <- md4op2 d a b c X.[4] 5
            c <- md4op2 c d a b X.[8] 9
            b <- md4op2 b c d a X.[12] 13
            a <- md4op2 a b c d X.[1] 3
            d <- md4op2 d a b c X.[5] 5
            c <- md4op2 c d a b X.[9] 9
            b <- md4op2 b c d a X.[13] 13
            a <- md4op2 a b c d X.[2] 3
            d <- md4op2 d a b c X.[6] 5
            c <- md4op2 c d a b X.[10] 9
            b <- md4op2 b c d a X.[14] 13
            a <- md4op2 a b c d X.[3] 3
            d <- md4op2 d a b c X.[7] 5
            c <- md4op2 c d a b X.[11] 9
            b <- md4op2 b c d a X.[15] 13
            // ROUND 3
            a <- md4op3 a b c d X.[0] 3
            d <- md4op3 d a b c X.[8] 9
            c <- md4op3 c d a b X.[4] 11
            b <- md4op3 b c d a X.[12] 15
            a <- md4op3 a b c d X.[2] 3
            d <- md4op3 d a b c X.[10] 9
            c <- md4op3 c d a b X.[6] 11
            b <- md4op3 b c d a X.[14] 15
            a <- md4op3 a b c d X.[1] 3
            d <- md4op3 d a b c X.[9] 9
            c <- md4op3 c d a b X.[5] 11
            b <- md4op3 b c d a X.[13] 15
            a <- md4op3 a b c d X.[3] 3
            d <- md4op3 d a b c X.[11] 9
            c <- md4op3 c d a b X.[7] 11
            b <- md4op3 b c d a X.[15] 15
            
            a <- a + aa
            b <- b + bb
            c <- c + cc
            d <- d + dd
        )
    // hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
    Array.concat [|
        (BitConverter.GetBytes a);
        (BitConverter.GetBytes b);
        (BitConverter.GetBytes c);
        (BitConverter.GetBytes d);
    |]

let md4mac (key: byte[]) (message: byte[]) = Array.append key message |> md4

let hmac (hash: (byte[] -> byte[])) (blockSize: int) (key: byte[]) (message: byte[]) =
    let keyP =
        if (key.Length > blockSize) then
            let hk = hash key
            Array.create (blockSize - hk.Length) 0uy |> Array.append hk
        else
            Array.create (blockSize - key.Length) 0uy |> Array.append key
    let oKeyPad =
        Array.create blockSize 0x5cuy
        |> Data.xor keyP
    let iKeyPad =
        Array.create blockSize 0x36uy
        |> Data.xor keyP
    let h1 = hash (Array.append iKeyPad message)
    hash (Array.append oKeyPad h1)

let hmacsha1 = hmac sha1 64

let hmacmd4 = hmac md4 64

let sha256 (data: byte[]): byte[] =
    (new SHA256Managed()).ComputeHash data