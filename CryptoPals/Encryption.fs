module Crypto.Encryption

open Crypto.Data
open System.Text

let repeatingKeyXor (data: Data) (key: string): Data =
    let length = Array.length data.data
    let times = length/(String.length key)
    let last = length%(String.length key)
    let repeatString = (String.replicate times key) + key.[..(last-1)]
    let repeatingKey = Data(Encoding.ASCII.GetBytes repeatString)
    data ^^^ repeatingKey
    