namespace Libplanet.Base

open System
open System.Diagnostics.Contracts

module ByteUtils =

    [<Pure>]
    let ParseHex (hex : string) : byte[] =
        [| for i in 0 .. (hex.Length / 2) - 1 ->
                Convert.ToByte(hex.Substring(i * 2, 2), 16) |]

    [<Pure>]
    let Hex (bytes : byte[]) : string =
        (BitConverter.ToString bytes).Replace("-", String.Empty).ToLower()

    [<Pure>]
    let CalculateHashCode (bytes : byte[]) : int =
        Array.fold
            (fun current t -> current * (bytes.Length + 1) + int t)
            0
            bytes
