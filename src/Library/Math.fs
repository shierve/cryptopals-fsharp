module Crypto.Math

open System.Numerics

let modExp a b n =
    BigInteger.ModPow(a, b, n)

let modulo (a: bigint) b =
    ((a % b) + b) % b

/// Modular inverse. Uses extended Euclid algorithm.
let invMod a n =
    let rec extEuclid a b =
        if (b = 0I) then (a, 1I, 0I) 
        else let (d', x', y') = extEuclid b (a % b)
             let (d, x, y) = (d', y', x' - (a/b)*y')
             (d, x, y)
    let (d, x, y) = extEuclid a n
    if (x < 0I) then (x+n) else x

/// Greatest common divistor. Uses the Euclid algorithm.
let rec gcd a b =
    if b = 0I then a
    else gcd b (a % b)

/// Returns a BigInteger random number from 0 (inclusive) to max (exclusive).
let randomBigInteger (max:bigint) =
    let rec getNumBytesInRange num bytes =
        if max < num then bytes
        else getNumBytesInRange (num * 256I) bytes+1
    let bytesNeeded = getNumBytesInRange 256I 1
    let bytes = Data.randomBytes (bytesNeeded+1)
    bytes.[bytesNeeded] <- 0uy
    (bigint bytes) % max

/// Returns a random number with certain number of bits
let nextBigintBits (rand:System.Random) bits =
    let rec next' (r:System.Random) b acc =
        if b <= 0 then acc
        else next' r (b-1) (acc*2I + new bigint(r.Next(2)))
    next' rand (bits-1) 1I // To preserve the bit length

/// Cell type used in bigint_generator.
type cell = {
                table : bigint array
                m : bigint
                mutable j : int
                mutable k : int
            }

/// An additive random bigint generator.
/// Generates bigint's in range [<c>0</c>, <c>n</c>).
/// Uses algorithm 3.2.2A from TAOCP.
let bigintGenerator n =
    let x = {
                table = Array.create 55 0I
                m = n
                j = 23
                k = 54
            }
    let rand = (new System.Random())
    let bitsMax = (int)(System.Numerics.BigInteger.Log (n, 2.))
    for i=0 to 54 do x.table.[i] <- (nextBigintBits rand (rand.Next(bitsMax)+1));
    fun () -> (x.table.[x.k] <- (x.table.[x.k] + x.table.[x.j]) % x.m;
               let res = x.table.[x.k];
               x.j <- if x.j = 0 then 54 else (x.j - 1);
               x.k <- if x.k = 0 then 54 else (x.k - 1);
               res)

/// Array of small prime numbers. Used in primality test for optimization.
let smallPrimes = [|2I; 3I; 5I; 7I; 11I; 13I; 17I; 19I; 23I; 29I; 31I; 37I; 41I; 43I; 47I; 53I; 59I; 61I; 67I; 71I; 73I;
                     79I; 83I; 89I; 97I; 101I; 103I; 107I; 109I; 113I; 127I; 131I; 137I; 139I; 149I; 151I; 157I; 163I; 
                     167I; 173I; 179I; 181I; 191I; 193I; 197I; 199I; 211I; 223I; 227I; 229I; 233I; 239I; 241I; 251I;
                     257I; 263I; 269I; 271I; 277I; 281I; 283I; 293I; 307I; 311I; 313I; 317I; 331I; 337I; 347I; 349I;
                     353I; 359I; 367I; 373I; 379I; 383I; 389I; 397I; 401I; 409I; 419I; 421I; 431I; 433I; 439I; 443I;
                     449I; 457I; 461I; 463I; 467I; 479I; 487I; 491I; 499I; 503I; 509I; 521I; 523I; 541I; 547I; 557I;
                     563I; 569I; 571I; 577I; 587I; 593I; 599I; 601I; 607I; 613I; 617I; 619I; 631I; 641I; 643I; 647I;
                     653I; 659I; 661I; 673I; 677I; 683I; 691I; 701I; 709I; 719I; 727I; 733I; 739I; 743I; 751I; 757I;
                     761I; 769I; 773I; 787I; 797I; 809I; 811I; 821I; 823I; 827I; 829I; 839I; 853I; 857I; 859I; 863I;
                     877I; 881I; 883I; 887I; 907I; 911I; 919I; 929I; 937I; 941I; 947I; 953I; 967I; 971I; 977I; 983I; 991I; 997I|]

/// Miller-Rabin probabilistic primality test.
/// P(mistake) = 2^(-s), where s is the number of iterations.
let isPrime x s =
    let getTu n =
        let n' = n - 1I
        let rec calcTu t u = 
            if u % 2I = 1I then (t, u)
            else calcTu (t+1) (u/2I)
        calcTu 0 n'

    let witness a n =
        let (t, u) = getTu n
        let mutable prev = modExp a u n
        let mutable next = (prev*prev) % n
        let mutable nontrivialRoots = false
        for i = 1 to t do
            nontrivialRoots <- nontrivialRoots || (next = 1I && prev <> 1I && prev <> (n-1I));
            prev <- next; next <- (prev*prev) % n
        (prev <> 1I || nontrivialRoots)

    let millerRabin n s =
        let rand = bigintGenerator (n-2I)
        let rec test c = 
            if c = 0 then true
            else
                let a = rand() + 2I
                //printf "a = %A " a;
                if (witness a n) then false
                else test (c-1)
        test s

    let divisibleBySmallPrime n =
        let rec check i = 
            if i = 168
                then false
                else if n > smallPrimes.[i]
                        then if (n % smallPrimes.[i] = 0I)
                                then true
                                else check (i+1)
                        else false
        check 0

    if (divisibleBySmallPrime x) // Optimization using a table of small primes
        then false
        else if (x = 1I || Array.exists (fun elem -> elem = x) smallPrimes) // => very small keys (p < 1000)
                then true
    else (millerRabin x s) // Miller-Rabin test call

/// Generates a prime bigint of specified bit-length.
/// Requires a System.Random object to be passed as a parameter.
/// The s parameter denotes the number of iterations in the primality test.
let nextPrime rand bits s =
    let rec searchPrime x =
        if (isPrime x s) then x
        else searchPrime (x + 2I)
    let randomBigint = nextBigintBits rand bits
    let candidate = if (randomBigint % 2I = 0I) then (randomBigint + 1I) else randomBigint
    searchPrime candidate
    
/// Generates a prime bigint of specified bit-length that satisfies the given predicate.
/// Requires a <c>System.Random object</c> to be passed as a parameter.
/// The <c>s</c> parameter denotes the number of iterations in the primality test.
let nextPrimePredicate rand bits s predicate =
    let rec searchPrime x attempts =
        if ((isPrime x s) && (predicate x)) then
            x
        else searchPrime (x + 2I) (attempts+1)
    let randomBigint = nextBigintBits rand bits
    let candidate = if (randomBigint % 2I = 0I) then (randomBigint + 1I) else randomBigint
    searchPrime candidate 1

/// Newton's method. Returns last number s for which s**k does not exceed n
let iroot k (n: bigint) =
    let k1 = k - 1
    let mutable s = n + 1I
    let mutable u = n
    while u < s do
        s <- u
        u <- ((u * bigint(k1)) + n / (u ** k1)) / bigint(k)
    s
