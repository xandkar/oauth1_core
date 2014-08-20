-module(oauth1_signature_base_string_uri).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-type t() ::
    binary().


-spec cons(?uri:t()) ->
    t().
cons(URI) ->
    URIBin = ?uri:to_bin(URI, do_not_include_query),
    cow_qs:urlencode(URIBin).
