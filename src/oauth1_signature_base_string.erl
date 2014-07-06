-module(oauth1_signature_base_string).

-include_lib("oauth1_signature_base_string.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-opaque t() ::
    binary().

-type args_cons() ::
    #oauth1_signature_base_string_args_cons{}.


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_base_string_args_cons
    { signature_method     = _
    , http_req_method      = _
    , http_req_host        = _
    , resource             = _
    , consumer_key         = _
    , timestamp            = _
    , nonce                = _
    }
) ->
    error(not_implemented).
