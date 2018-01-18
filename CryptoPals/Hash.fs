module Crypto.Hash

open System


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
    let mutable ml: uint64 = (uint64 data.Length) * 8UL

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
                    if (0 <= i && i <= 19) then
                        (
                            (b &&& c) ||| ((b ^^^ 0xFFFFFFFFul) &&& d),
                            0x5A827999ul
                        )
                    else if 20 <= i && i <= 39 then
                        (
                            (b ^^^ c) ^^^ d,
                            0x6ED9EBA1ul
                        )
                    else if 40 <= i && i <= 59 then
                        (
                            (b &&& c) ||| (b &&& d) ||| (c &&& d),
                            0x8F1BBCDCul
                        )
                    else
                        (
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

