-module(oauth1_random_string).

-export_type(
    [ t/0
    , error/0
    ]).

-export(
    [ generate/0
    ]).


-type error() ::
    low_entropy.

-type t() ::
    binary().


-spec generate() ->
    hope_result:t(t(), error()).
generate() ->
    Generator = hope_result:lift_exn(fun crypto:strong_rand_bytes/1),
    case Generator(1024)
    of  {error, {error, low_entropy}=Error} ->
            Error
    ;   {ok, RandomBytes} ->
            Digest    = crypto:hash(ripemd160, RandomBytes),
            DigestHex = bstr:hexencode(Digest),
            {ok, DigestHex}
    end.
