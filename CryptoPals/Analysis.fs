module Crypto.Analysis

open Crypto


let englishFrequency =
    Map.ofList [
        byte 'a', 0.08167;
        byte 'b', 0.01492;
        byte 'c', 0.02782;
        byte 'd', 0.04253;
        byte 'e', 0.12702;
        byte 'f', 0.02228;
        byte 'g', 0.02015;
        byte 'h', 0.06094;
        byte 'i', 0.06966;
        byte 'j', 0.00153;
        byte 'k', 0.00772;
        byte 'l', 0.04025;
        byte 'm', 0.02406;
        byte 'n', 0.06749;
        byte 'o', 0.07507;
        byte 'p', 0.01929;
        byte 'q', 0.00095;
        byte 'r', 0.05987;
        byte 's', 0.06327;
        byte 't', 0.09056;
        byte 'u', 0.02758;
        byte 'v', 0.00978;
        byte 'w', 0.02360;
        byte 'x', 0.00150;
        byte 'y', 0.01974;
        byte 'z', 0.00074;
    ]


let frequencyEvaluation (d: byte[]): float =
    // Get data in lower case (only letters)
    let bytes =
        d
        |> Array.map ( fun b -> if (b > byte 'A' && b < byte 'Z') then (b-65uy+97uy) else b )
        |> Array.filter (fun b -> b > 96uy && b < 123uy)
    let total = Array.length bytes
    // Generate map of frequencies
    let frequencyMap: Map<byte, float> =
        List.fold (fun m letter ->
            let occurences = Array.length (Array.filter ((=) (byte letter)) bytes)
            m.Add(byte letter, (float occurences)/(float total))
        ) Map.empty [(int 'a') .. (int 'z')]
    // Transform maps into lists of floats
    let expected: List<float> = Map.toList englishFrequency |> List.map (fun (_, f) -> f)
    let observed: List<float> = Map.toList frequencyMap |> List.map (fun (_, f) -> f)
    // Calculate mean square error
    let meanSqErr: float =
        List.map2 (fun f1 f2 -> (f1-f2)**(float 2)) expected observed
        |> List.average
    // Apply a penalty for too many special characters (not counting spaces)
    let spaces = Array.fold (fun acc ch -> if ch = byte ' ' then acc+1 else acc) 0 d
    let symbolFreq: float = 1.0 - ( float (bytes.Length + spaces) / float d.Length )
    let penalizer = 1.0 + (symbolFreq)
    meanSqErr * penalizer


let frequencySort (a: (byte * byte[])[]): (byte * byte[] * float)[] =
    let isWeirdAscii ch =
        (ch < 32uy || ch > 126uy) && ch <> 8uy && ch <> 9uy && ch <> 10uy
    a
    |> Array.filter (fun (_, d) -> Array.forall (isWeirdAscii >> not) d)
    |> Array.map (fun (k, d) -> (k, d, frequencyEvaluation d))
    |> Array.sortBy (fun (_, _, f) -> f)


let tryBestKey (cipher: byte[]): (byte * byte[] * float) option =
    let keys = List.map ( fun k -> (byte k, (Data.singleByteXor cipher (byte k))) ) [0 .. 255] |> List.toArray |> frequencySort
    if Array.isEmpty keys then None
    else Some keys.[0]


let hammingDistance (a: byte[]) (b: byte[]): int =
    let bitsInByte (by: byte): int =
        let mutable b: byte = by
        let mutable bits = 0
        for _i = 0 to 7 do
            if (b%2uy <> 0uy) then bits <- bits + 1
            else ()
            b <- b >>> 1;
        bits
    Array.map2 ( ^^^ ) a b
    |> Array.sumBy (bitsInByte)


let bestKeySizes (cipher: byte[]): int[] =
    List.map
        (fun size ->
            let par = [ for a in 0 .. 3 do yield (Array.sub cipher (size*a) size) ] 
            let distances = 
                [
                    (hammingDistance par.[0] par.[1]);
                    (hammingDistance par.[0] par.[2]);
                    (hammingDistance par.[0] par.[3]);
                    (hammingDistance par.[1] par.[2]);
                    (hammingDistance par.[1] par.[3]);
                    (hammingDistance par.[2] par.[3])
                ]
            (size, (List.averageBy float distances)/float size)
        ) [2..50]
        //) [2..(Array.length cipher)/4] // at max
    |> List.sortBy (fun (_, d) -> d)
    |> List.map (fun (s, _) -> s)
    |> Array.ofList


let partitionAndTranspose (data) (ks: int) =
    // Preparation function for breaking repeating key
    [|
        for n in 0 .. ks-1 do
            yield
                Array.indexed data
                |> Array.filter (fun (i, _) -> i%ks = n)
                |> Array.map (fun (_, b) -> b)
    |]

let byteAtATime (encrypt: byte[] -> byte[]): byte[] =
    // Recovers append string from function that ECB appends then ECB encrypts
    // 1. Find block size
    let emptyEncrypt = encrypt (Array.empty)
    let (middleSize, jumpEncrypt) =
        List.find (fun (_, c) -> (Array.length >> ((<>) emptyEncrypt.Length)) c)
            (List.map (fun s -> Array.create s 0uy |> encrypt |> (fun ci -> (s, ci))) [1..64])
    let blockSize = jumpEncrypt.Length - emptyEncrypt.Length
    // |XXXXXXXXXX--+---|+---+---+---+---|AAAAAA--+---+---|+---+---+---+---|
    // 2. Find prepend size
    let chunked = (Array.create (blockSize*3) 0uy) |> encrypt |> Array.chunkBySize blockSize
    let repeating = chunked |> Array.indexed |> Array.findIndex (fun (i, b) -> b = chunked.[i+1])
    let inequalSize: int =
        List.find (fun (_, c: byte[][]) -> c.[repeating] <> c.[repeating+1])
            (List.map (fun s -> Array.create s 0uy |> encrypt |> Array.chunkBySize blockSize |> (fun c -> (s, c)))
                [for i = (blockSize*3) downto blockSize do yield i])
        |> (fun (i, _) -> i)
    let prependSize = (blockSize - ((inequalSize+1)%blockSize))+(blockSize*(repeating-1))
    // 3. Find append size
    let tSize = encrypt (Array.create (middleSize-1) 0uy) |> Array.length
    let appendSize = tSize - prependSize - middleSize
    printfn "Block size: %A. Prepend size: %A. Append size: %A.\n" blockSize prependSize appendSize
    // 4. ???
    let append: byte[] = Array.create appendSize 0uy
    let prepadSize = (blockSize-(prependSize%blockSize))
    let mutable testBlock = Array.create (prepadSize + blockSize-1) 0uy
    let baseBlock = (prependSize + (blockSize - (prependSize % blockSize)))/blockSize
    let testBytes = [0..128] |> List.map byte
    for i = 0 to (appendSize-1) do
        let currentBlock = baseBlock + (i/blockSize)
        let objective =
            encrypt (Array.create (prepadSize + blockSize - (i%blockSize) - 1) 0uy)
            |> Array.chunkBySize blockSize
            |> (fun blocks -> blocks.[currentBlock])
        let foundByte = List.find (fun x -> 
            let blocks = (encrypt (Array.append testBlock [|x|])) |> Array.chunkBySize blockSize
            blocks.[baseBlock] = objective ) testBytes
        append.[i] <- foundByte
        printf "%c" (System.Convert.ToChar foundByte)
        testBlock <- Data.shiftLeft testBlock foundByte
    // 5. Profit
    append

let paddingOracleAttack (oracle: (byte[] * byte[]) -> bool) (iv: byte[], cipher: byte[]) =
    let blockSize = Array.length iv
    let blocks = Array.chunkBySize blockSize cipher
    // Define function to break a block
    let breakBlock (previous: byte[], block: byte[]) =
        let mutable testBlock: byte[] = Array.zeroCreate blockSize
        let plainBlock: byte[] = Array.zeroCreate blockSize
        // last byte
        let bytes = seq { for i in 0 .. 255 -> byte i }
        plainBlock.[blockSize-1] <- Seq.find (fun b ->
            testBlock.[blockSize-1] <- (b ^^^ 1uy ^^^ previous.[blockSize-1])
            if oracle (testBlock, block) then
                testBlock.[blockSize-2] <- testBlock.[blockSize-2] ^^^ 255uy
                oracle (testBlock, block)
            else
                false
        ) bytes
        // the rest
        for i = 2 to blockSize do
            let pos = blockSize-i
            let plainopt = Seq.tryFind (fun b ->
                testBlock <- Array.map (fun n -> plainBlock.[n] ^^^ (byte i) ^^^ previous.[n]) [| 0..(blockSize-1) |]
                testBlock.[pos] <- (b ^^^ (byte i) ^^^ previous.[pos])
                oracle (testBlock, block) ) bytes
            plainBlock.[pos] <- match plainopt with
                                | Some b -> b
                                | None -> 63uy
        plainBlock
    // Separate in groups of two blocks (tuples)
    let tuples = Array.scan ( fun (_, last) block -> (last, block) ) (iv, blocks.[0]) blocks.[1..]
    Array.collect breakBlock tuples

let mt19937Untamper (n: uint32) =
    let mutable z = n
    let mutable y = z ^^^ (z >>> 18)
    // y = y xor ((y << 15) && 0xefc..)
    z <- y ^^^ ((y <<< 15) &&& 0xefc60000u)
    // y = y xor ((y << 7) && 0x9d2c...)
    y <- z ^^^ ((z <<< 7) &&& 0x9d2c5680u)
    y <- z ^^^ ((y <<< 7) &&& 0x9d2c5680u)
    y <- z ^^^ ((y <<< 7) &&& 0x9d2c5680u)
    z <- z ^^^ ((y <<< 7) &&& 0x9d2c5680u)
    // y xor (y >> 11)
    y <- z ^^^ (z >>> 11)
    z ^^^ (y >>> 11)

