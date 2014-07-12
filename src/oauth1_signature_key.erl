-module(oauth1_signature_key).

-export_type(
    [ t/0
    ]).

-export(
    [ cons/2
    ]).


-type t() ::
    binary().


-spec cons(ClientSharedSecret, hope_option:t(TokenSharedSecret)) -> t()
    when ClientSharedSecret :: oauth1_credentials:secret(client)
       , TokenSharedSecret  :: oauth1_credentials:secret(tmp | token)
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
    % TODO: Percent-encode both secrets
    <<ClientSecret/binary, "&", TokenSecret/binary>>.
