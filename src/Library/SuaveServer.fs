namespace Crypto.SuaveServer

open Newtonsoft.Json
open Newtonsoft.Json.Serialization
open Suave
open Suave.Filters
open Suave.Operators
open System.Numerics
open System.Collections.Concurrent
open Suave.State.CookieStateStore
open Crypto
open Crypto.Math


type User = {
    I : string
    Salt: byte[]
    V : BigInteger
    ActiveSession : bool
    SessionKey : byte[]
}

type UserCredentials = {
    I : string
    p : string
}

type NewSessionRequestData = {
    I: string
    A: string
}

type NewSessionResponseData = {
    B: string
    Salt: string
}

type ValidationRequestData = {
    I: string
    k: string
}

type ValidationResponseData = {
    message: string
}

type UserRepository = {
    Add : User -> Option<User>
    Find : string -> Option<User>
    Update : User -> Option<User>
}

module UserDB =
    let private users = new ConcurrentDictionary<string, User>()

    let add (user: User) =
        let copy = { user with I = user.I }
        if users.TryAdd(copy.I, copy) then
            Some(copy)
        else 
            None

    let find i =
        let (success, value) = users.TryGetValue(i)
        if success then
            Some(value)
        else 
            None
    
    let update (user: User) =
        let tryupdate current =
            if users.TryUpdate(user.I, user, current) then
                Some(user)
            else 
                None
        find user.I |> Option.bind tryupdate

    let UserDB = {
        Add = add
        Find = find
        Update = update
    }


module Controller =
    let fromJson<'a> json =
        let obj = JsonConvert.DeserializeObject(json, typeof<'a>) 
        if isNull obj then
            None
        else
            Some(obj :?> 'a)

    let getResourceFromReq<'a> (req : HttpRequest) =
        let getString rawForm =
            System.Text.Encoding.UTF8.GetString(rawForm)
        req.rawForm |> getString |> fromJson<'a>

    let JSON value =
        let settings = JsonSerializerSettings()
        settings.ContractResolver <- CamelCasePropertyNamesContractResolver()

        JsonConvert.SerializeObject(value, settings)
        |> Successful.OK
        >=> Writers.setMimeType "application/json; charset=utf-8"
    
    let handleResource f requestError = function
        | Some r -> r |> f
        | _ -> requestError

    let handleResourceBADREQUEST = 
        (fun f -> handleResource f (RequestErrors.BAD_REQUEST "No Resource from request"))

    let handleResourceNOTFOUND = 
        (fun f -> handleResource f (RequestErrors.NOT_FOUND "Resource not found"))

    let handleResourceCONFLICT = 
        (fun f -> handleResource f (RequestErrors.CONFLICT "Resource already exists"))

module SRP =
    let N =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        + "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        + "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        + "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        + "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        + "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        + "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        + "fffffffffffff"
        |> Data.bigIntFromHex
    let g = 2I
    let k = 3I

module UserController =
    let find db =
        db.Find 
        >> (Controller.handleResourceNOTFOUND Controller.JSON)

    let newSession db (ctx: HttpContext): Async<HttpContext option> =
        let genSession (user: User) (ns: NewSessionRequestData) =
            let A = Data.bigIntFromHex ns.A
            let b = randomBigInteger SRP.N
            let B = (SRP.k * user.V + (modExp SRP.g b SRP.N)) % SRP.N
            let u = Array.append (A.ToByteArray ()) (B.ToByteArray ()) |> Hash.sha256 |> Data.toBigInt
            let s = modExp (A * (modExp user.V u SRP.N)) b SRP.N
            let keyS = Hash.sha256 (s.ToByteArray ())
            printfn "k: %A" (Data.asHex keyS)
            (B, keyS)
        let createSession (ns: NewSessionRequestData) =
            db.Find ns.I
            |> Controller.handleResourceNOTFOUND (fun user ->
                let (B, k) = genSession user ns
                let newUser = {
                    I = user.I
                    Salt = user.Salt
                    V = user.V
                    ActiveSession = true
                    SessionKey = k
                }
                db.Update newUser
                |> (Controller.handleResourceNOTFOUND (fun _ ->
                    {
                        B = (Data.fromBigInt B |> Data.asHex)
                        Salt = (Data.asHex user.Salt)
                    } |> Controller.JSON
                ))
            )
        request (Controller.getResourceFromReq >> (Controller.handleResourceBADREQUEST createSession)) ctx

    let add db (ctx: HttpContext) =
        let genUser (r: UserCredentials) =
            let salt = Data.randomBytes 4
            let xH = Array.concat [| salt; (Data.fromString r.I); (Data.fromString r.p) |] |> Hash.sha256 |> Data.toBigInt
            let v = modExp SRP.g xH SRP.N
            {
                I = r.I
                Salt = salt
                V = v
                ActiveSession = false
                SessionKey = Array.zeroCreate 16
            }
        let addDb =
            (genUser >> db.Add >> (Controller.handleResourceCONFLICT Controller.JSON))
        request (Controller.getResourceFromReq >> (Controller.handleResourceBADREQUEST addDb)) ctx |> ignore
        Suave.Successful.OK "User Added" ctx

    let validate db (ctx: HttpContext) =
        let validateKey (ns: ValidationRequestData) =
            db.Find ns.I
            |> Controller.handleResourceNOTFOUND (fun user ->
                let hmacKey = Hash.hmacsha256 user.SessionKey user.Salt
                if ns.k = (Data.asHex hmacKey) then
                    {
                        message = "OK"
                    } |> Controller.JSON
                else
                    {
                        message = "Invalid"
                    } |> Controller.JSON
            )
        request
            (Controller.getResourceFromReq >> (Controller.handleResourceBADREQUEST validateKey)) ctx


    let UserController (db: UserRepository) = 
        pathStarts "/api/" >=> choose [
            POST >=> path "/api/user/new" >=> (add db)
            POST >=> path "/api/user/newsession" >=> (newSession db)
            POST >=> path "/api/user/validatesession" >=> (validate db)
            // DELETE >=> pathScan "/api/todo/%s" (remove db)
            // PUT >=> pathScan "/api/todo/%s" (update db)  
        ]
