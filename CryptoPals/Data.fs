namespace Crypto.Data

open Crypto.Conversion
open System
open System.Text

type Data(data) =
    member this.data: byte[] = data

    static member asB64 (d: Data): string =
        Convert.ToBase64String d.data

    static member asHex (d: Data): string =
        d.data
        |> Array.map (fun (x : byte) -> String.Format("{0:X2}", x))
        |> String.concat String.Empty

    static member asString (d: Data): string =
        Encoding.ASCII.GetString d.data

    static member fromHex (s: string) =
        let d =
            s
            |> Seq.windowed 2
            |> Seq.mapi (fun i j -> (i,j))
            |> Seq.filter (fun (i, _) -> i % 2=0)
            |> Seq.map (fun (_,j) -> Byte.Parse(System.String(j),System.Globalization.NumberStyles.AllowHexSpecifier))
            |> Array.ofSeq
        Data(d)

    static member fromString (s: string) =
        Data(Encoding.ASCII.GetBytes s)

    static member (^^^) (a: Data, b: Data) =
        Data(Array.map2 ( ^^^ ) a.data b.data)
    
    static member (^^) (a: Data, b: byte) =
        let bdata = Array.create (Array.length (a.data)) b
        Data(Array.map2 ( ^^^ ) a.data bdata)
