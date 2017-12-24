module Crypto.Encryption

open Crypto
open System.Text

let repeatingKeyXor (data: byte[]) (key: string): byte[] =
    let length = Array.length data
    let times = length/(String.length key)
    let last = length%(String.length key)
    let repeatString = (String.replicate times key) + key.[..(last-1)]
    let repeatingKey = Encoding.ASCII.GetBytes repeatString
    Data.xor data repeatingKey
    