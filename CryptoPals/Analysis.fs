module Crypto.Analysis

open Crypto.Data


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


let frequencyEvaluation (d: Data): float =
    // Get data in lower case (only letters)
    let bytes =
        d.data
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
    let spaces = Array.fold (fun acc ch -> if ch = byte ' ' then acc+1 else acc) 0 d.data
    let symbolFreq: float = 1.0 - ( float ((Array.length bytes) + spaces) / float (Array.length d.data) )
    let penalizer = 1.0 + symbolFreq
    meanSqErr * penalizer


let frequencySort (a: (byte * Data)[]): (byte * Data * float)[] =
    let isWeirdAscii ch =
        (ch < 32uy || ch > 126uy) && ch <> 8uy && ch <> 9uy && ch <> 10uy
    a
    |> Array.filter (fun (_, d) -> Array.forall (isWeirdAscii >> not) d.data)
    |> Array.map (fun (k, d) -> (k, d, frequencyEvaluation d))
    |> Array.sortBy (fun (_, _, f) -> f)


let bestKey (cipher: Data): (byte * Data * float) option =
    let keys = List.map ( fun k -> (byte k, (cipher ^^ (byte k))) ) [0 .. 255] |> List.toArray |> frequencySort
    if Array.isEmpty keys then None
    else Some keys.[0]


let hammingDistance (a: Data) (b: Data): int =
    let bitsInByte (by: byte): int =
        let mutable b: byte = by
        let mutable bits = 0
        for i = 0 to 7 do
            if (b%2uy <> 0uy) then bits <- bits + 1
            else ()
            b <- b >>> 1;
        bits
    Array.map2 ( ^^^ ) a.data b.data
    |> Array.sumBy (bitsInByte)
