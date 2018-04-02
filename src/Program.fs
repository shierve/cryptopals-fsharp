open Crypto.Set1
open Crypto.Set2
open Crypto.Set3
open Crypto.Set4
open Crypto.Set5

[<EntryPoint>]
let main argv =
    let challenges: (unit -> unit)[] =
        [|
            ch1; ch2; ch3; ch4; ch5; ch6; ch7; ch8;  // SET 1
            ch9; ch10; ch11; ch12; ch13; ch14; ch15; ch16;  // SET 2
            ch17; ch18; ch19; ch20; ch21; ch22; ch23; ch24;  // SET 3
            ch25; ch26; ch27; ch28; ch29; ch30; ch31; ch32;  // SET 4
            ch33; ch34; ch35; ch36; ch37; ch38; ch39; ch40; // SET 5
        |]
    if argv.Length > 0 then
        if (int argv.[0]) = -1 then
            startSuaveServer ()
        else
            let challenge: (unit -> unit) = challenges.[(int argv.[0])-1]
            challenge ()
    else
        let challenge: (unit -> unit) = challenges.[challenges.Length-1]
        challenge ()
    0 // return an integer exit code
