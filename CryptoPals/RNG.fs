module Crypto.RNG


type State = { mt: uint32[]; mutable mti: int; }

let n = 624
let state = { mt = Array.create n 0u; mti = 0 }

let initRng seed =
    let ml = 1812433253u
    state.mt.[0] <- (seed)
    for i = 1 to n-1 do
        let mtprev = state.mt.[i-1]
        state.mt.[i] <- ml * (mtprev ^^^ (mtprev >>> 30)) + uint32 i
    state.mti <- 0

let genNumbers () =
    for i = 0 to n-1 do
        let y = (state.mt.[i] &&& 0x80000000u) + (state.mt.[(i+1) % n] &&& 0x7fffffffu)
        state.mt.[i] <- state.mt.[(i+397) % n] ^^^ (y >>> 1)
        if y % 2u <> 0u then state.mt.[i] <- state.mt.[i] ^^^ 0x9908b0dfu

let randInt32 () =
    if state.mti = 0 then genNumbers ()
    let mutable y = state.mt.[state.mti]
    y <- y ^^^ (y >>> 11)
    y <- y ^^^ ((y <<< 7) &&& 0x9d2c5680u)
    y <- y ^^^ ((y <<< 15) &&& 0xefc60000u)
    y <- y ^^^ (y >>> 18)
    state.mti <- (state.mti + 1) % n
    y

let randInt () = int (randInt32 ())

let seed (n: int) = initRng (uint32 n)