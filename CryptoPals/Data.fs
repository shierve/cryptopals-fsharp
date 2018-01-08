module Crypto.Data

open System
open System.Text


exception PaddingException of string

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
    else raise (PaddingException "Invalid Padding")

let asB64 (d: byte[]): string = Convert.ToBase64String d

let asHex (d: byte[]): string =
    d
    |> Array.map (fun (x : byte) -> String.Format("{0:X2}", x))
    |> String.concat String.Empty

let asString (d: byte[]): string =
    (removePadding d)
    |> Encoding.ASCII.GetString

let fromB64 (s: string) = Convert.FromBase64String s

let fromHex (s: string) =
    s
    |> Seq.windowed 2
    |> Seq.mapi (fun i j -> (i,j))
    |> Seq.filter (fun (i, _) -> i % 2=0)
    |> Seq.map (fun (_,j) -> Byte.Parse(System.String(j),System.Globalization.NumberStyles.AllowHexSpecifier))
    |> Array.ofSeq

let fromString (s: string) = Encoding.ASCII.GetBytes s

let xor (a: byte[]) (b: byte[]) = Array.map2 ( ^^^ ) a b

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
