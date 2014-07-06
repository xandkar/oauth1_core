-module(oauth1_signature_key).

-export_type(
    [ t/0
    ]).

-export(
    [ cons/2
    ]).


-type t() ::
    binary().


-spec cons(ClientSharedSecret, TokenSharedSecret) -> t()
    when ClientSharedSecret :: oauth1_credentials:secret(client)
       , TokenSharedSecret  :: oauth1_credentials:secret(tmp | token)
       .
cons({client, <<ClientSecret/binary>>}, {Type, <<TokenSecret/binary>>})
when   Type =:= tmp
orelse Type =:= token ->
    % TODO: Percent-encode both secrets
    <<ClientSecret/binary, "&", TokenSecret/binary>>.
