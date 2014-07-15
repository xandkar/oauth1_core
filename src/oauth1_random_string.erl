-module(oauth1_random_string).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    ]).


-type t() ::
    binary().


-spec generate() ->
    t().
generate() ->
    RandomBytes = crypto:strong_rand_bytes(1024),
    Digest      = crypto:hash(ripemd160, RandomBytes),
    bstr:hexencode(Digest).
