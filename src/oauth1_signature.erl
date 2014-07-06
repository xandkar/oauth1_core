-module(oauth1_signature).

-include_lib("oauth1_signature.hrl").

-export_type(
    [ t/0
    , method/0
    , value/0
    ]).

-export(
    [ cons/1
    ]).


-type method() ::
    'HMAC_SHA1'.

-type value() ::
    binary().

-record(t,
    { method :: method()
    , value  :: value()
    }).

-opaque t() ::
    #t{}.

-type args_cons() ::
    #oauth1_signature_args_cons{}.


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_args_cons
    { method               = _
    , http_req_method      = _
    , http_req_host        = _
    , resource             = _
    , consumer_key         = _
    , client_shared_secret = _
    , token_shared_secret  = _
    , timestamp            = _
    , nonce                = _
    }
) ->
    error(not_implemented).
