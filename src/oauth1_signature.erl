-module(oauth1_signature).

-include_lib("oauth1_module_abbreviations.hrl").
-include_lib("oauth1_signature.hrl").
-include_lib("oauth1_signature_base_string.hrl").

-export_type(
    [ t/0
    , method/0
    , digest/0
    ]).

-export(
    % Construct
    [ cons/1

    , method_of_bin/1
    , method_to_bin/1

    % Access (normal usage)
    , get_digest/1

    % Access (for tests)
    , get_key/1
    , get_text/1
    ]).


-type method() ::
    'HMAC_SHA1'.

-type digest() ::
    binary().

-record(t,
    { method :: method()
    , key    :: binary()
    , text   :: binary()
    , digest :: digest()
    }).

-opaque t() ::
    #t{}.

-type args_cons() ::
    #oauth1_signature_args_cons{}.


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_args_cons
    { method               = 'HMAC_SHA1' = Method
    , http_req_method      = HttpMeth
    , http_req_host        = HttpHost
    , resource             = Resource
    , consumer_key         = ConsumerKey
    , timestamp            = Timestamp
    , nonce                = Nonce

    , client_shared_secret = ClientSharedSecret

    , token                = TokenOpt
    , verifier             = VerifierOpt
    , callback             = CallbackURIOpt

    , version              = VersionOpt
    }
) ->
    {TokenIDOpt, TokenSharedSecretOpt} =
        case TokenOpt
        of  none ->
                {none, none}
        ;   {some, Token} ->
                TokenID     = ?credentials:get_id(Token),
                TokenSecret = ?credentials:get_secret(Token),
                {{some, TokenID}, {some, TokenSecret}}
        end,
    BaseStringArgs =
        #oauth1_signature_base_string_args_cons
        { signature_method = 'HMAC_SHA1'
        , http_req_method  = HttpMeth
        , http_req_host    = HttpHost
        , resource         = Resource
        , consumer_key     = ConsumerKey
        , timestamp        = Timestamp
        , nonce            = Nonce

        , token_id         = TokenIDOpt
        , verifier         = VerifierOpt
        , callback         = CallbackURIOpt

        , version          = VersionOpt
        },
    TokShaSecOpt = TokenSharedSecretOpt,
    Key          = ?signature_key:cons(ClientSharedSecret, TokShaSecOpt),
    Text         = ?signature_base_string:cons(BaseStringArgs),
    DigestBin    = crypto:hmac(sha, Key, Text),
    DigestBase64 = base64:encode(DigestBin),
    #t
    { method = Method
    , key    = Key
    , text   = Text
    % RFC 5849 says that digest must be url-encoded. We postpone doing so until
    % serialization by oauth1_parameters module (which url-encodes _all_
    % parameter values).
    , digest = DigestBase64
    }.

-spec get_digest(t()) ->
    digest().
get_digest(#t{digest=Digest}) ->
    Digest.

-spec get_key(t()) ->
    binary().
get_key(#t{key=Key}) ->
    Key.

-spec get_text(t()) ->
    binary().
get_text(#t{text=Text}) ->
    Text.

-spec method_to_bin(method()) ->
    binary().
method_to_bin('HMAC_SHA1') -> <<"HMAC-SHA1">>.

-spec method_of_bin(binary()) ->
    hope_result:t(method(), {signature_method_unsupported, binary()}).
method_of_bin(<<"HMAC-SHA1">>) -> {ok, 'HMAC_SHA1'};
method_of_bin(<<Bin/binary>> ) -> {error, {signature_method_unsupported, Bin}}.
