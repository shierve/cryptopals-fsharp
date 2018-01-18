module Crypto.Data

open System
open System.Text


exception PaddingException

let removePadding (data: byte[]) =
    // If invalid padding we throw an exception
    let lastByte = data.[data.Length-1]
    let valid =
        lastByte <> 0uy
        && lastByte <= byte data.Length
        && data.[(data.Length-(int lastByte))..]
        |> Array.forall ((=) lastByte)
    if valid then
        if data.Length = (int lastByte) then
            [||]
        else
            data.[..(data.Length-(int lastByte)-1)]
    else raise PaddingException

let tryRemovePadding (data: byte[]) =
    try
        removePadding data
    with
    | PaddingException -> data

let asB64 (d: byte[]): string = Convert.ToBase64String d

let asHex (d: byte[]): string =
    d
    |> Array.map (fun (x : byte) -> String.Format("{0:X2}", x))
    |> String.concat String.Empty

let asString (d: byte[]): string = Encoding.ASCII.GetString d

let fromB64 (s: string) = Convert.FromBase64String s

let fromHex (s: string) =
    s
    |> Seq.windowed 2
    |> Seq.mapi (fun i j -> (i,j))
    |> Seq.filter (fun (i, _) -> i % 2=0)
    |> Seq.map (fun (_,j) -> Byte.Parse(System.String(j),System.Globalization.NumberStyles.AllowHexSpecifier))
    |> Array.ofSeq

let fromString (s: string) = Encoding.ASCII.GetBytes s

let fromInt (number: int) =
    let bytes = BitConverter.GetBytes number
    if (not BitConverter.IsLittleEndian) then
        Array.rev bytes
    else
        bytes

let fromIntBigEndian (number: int) =
    let bytes = BitConverter.GetBytes number
    if (BitConverter.IsLittleEndian) then
        Array.rev bytes
    else
        bytes

let xor (a: byte[]) (b: byte[]) =
    if (a.Length <> b.Length) then
        let l = min a.Length b.Length
        let a' = a.[..l-1]
        let b' = b.[..l-1]
        Array.map2 ( ^^^ ) a' b'
    else
        Array.map2 ( ^^^ ) a b

let singleByteXor (a: byte[]) (b: byte) =
    Array.create a.Length b
    |> Array.map2 ( ^^^ ) a

let pad size (data: byte[]): byte[] =
    if data.Length%size = 0 then
        Array.create size (byte size) |> Array.append data
    else
        let paddingLength = size - (data.Length % size)
        Array.create paddingLength (byte paddingLength) |> Array.append data

let shiftLeft (data:byte[]) last =
    let a = Array.permute (fun i -> (data.Length+(i-1))%data.Length) data
    a.[a.Length-1] <- last
    a

let randomBytes (length: int) =
    let arr = Array.create length 0uy
    let rnd = System.Random()
    rnd.NextBytes(arr)
    arr