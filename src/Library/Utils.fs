module Crypto.Utils
open System
open FSharp.Core
open System.Net
open FSharp.Data

let unixTimestamp () =
    let dateTime = DateTime.Now
    let epoch = DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
    int (dateTime.ToUniversalTime() - epoch).TotalSeconds

let getUrl callback url =
    let req = WebRequest.Create(Uri(url))
    use resp = req.GetResponse()
    use stream = resp.GetResponseStream()
    use reader = new IO.StreamReader(stream)
    callback reader url

let myCallback (reader:IO.StreamReader) url =
    reader.ReadToEnd()
let fetchJson url = JsonValue.Parse(getUrl myCallback url)

let timeRequestAsync url =
    async {
        let uri = Uri(url)
        use webClient = new WebClient()

        // Execution of fetchHtmlAsync won't continue until the result
        // of AsyncDownloadString is bound.
        let start = System.DateTime.Now.Ticks
        try
            let _html = webClient.DownloadString(uri)
            return 1000000000L
        with
        | _ ->
            let stop = System.DateTime.Now.Ticks
            return stop-start
    }