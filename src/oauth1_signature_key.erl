-module(oauth1_signature_key).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/2
    ]).


-type t() ::
    binary().


-spec cons(ClientSharedSecret, hope_option:t(TokenSharedSecret)) -> t()
    when ClientSharedSecret :: ?credentials:secret(client)
       , TokenSharedSecret  :: ?credentials:secret(tmp | token)
       .
cons({client, <<ClientSecret/binary>>}, TokenSecretOpt) ->
    case TokenSecretOpt
    of  none ->
            concat(ClientSecret, <<>>)
    ;   {some, {tmp  , <<TokenSecret/binary>>}} ->
            concat(ClientSecret, TokenSecret)
    ;   {some, {token, <<TokenSecret/binary>>}} ->
            concat(ClientSecret, TokenSecret)
    end.

concat(<<ClientSecret/binary>>, <<TokenSecret/binary>>) ->
    ClientSecretEncoded = cow_qs:urlencode(ClientSecret),
    TokenSecretEncoded  = cow_qs:urlencode(TokenSecret),
    <<ClientSecretEncoded/binary, "&", TokenSecretEncoded/binary>>.
