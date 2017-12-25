module Crypto.Data

open System
open System.Text


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

let xor (a: byte[]) (b: byte[]) = Array.map2 ( ^^^ ) a b

let singleByteXor (a: byte[]) (b: byte) =
    Array.create (Array.length (a)) b
    |> Array.map2 ( ^^^ ) a
