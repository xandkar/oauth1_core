-module(oauth1_server).

-include_lib("oauth1_server.hrl").
-include_lib("oauth1_signature.hrl").

-export_type(
    [ error/0
    , args_initiate/0
    , args_token/0
    , args_validate_resource_request/0
    ]).

-export(
    [ register_new_client/0
    , initiate/1
    , authorize/1
    , token/1
    , validate_resource_request/1
    ]).

-type error_bad_request() ::
      parameters_unsupported
    | parameters_missing
    | parameters_duplicated
    | signature_method_unsupported
    .

-type error_unauthorized() ::
      signature_invalid
    | client_credentials_invalid
    | token_invalid
    | token_expired
    | verifier_invalid
    | nonce_invalid
    | nonce_used
    .

-type error() ::
      {bad_request  , error_bad_request()}
    | {unauthorized , error_unauthorized()}
    .

-type args_initiate() ::
    #oauth1_server_args_initiate{}.

-type args_token() ::
    #oauth1_server_args_token{}.

-type args_validate_resource_request() ::
    #oauth1_server_args_validate_resource_request{}.

-record(request_validation_state,
    { creds_client = none :: hope_option:t(oauth1_credentials:t(client))
    , creds_tmp    = none :: hope_option:t(oauth1_credentials:t(tmp))
    , verifier     = none :: hope_option:t(oauth1_verifier:t())

    , result       = none :: hope_option:t(term())
    }).


-define(not_implemented, error(not_implemented)).


%% @doc Generate and store a credentials pair {ClientID, ClientSecret).
%% @end
-spec register_new_client() ->
    hope_result:t({ID, Secret}, oauth1_storage:error())
    when ID     :: binary()
       , Secret :: binary()
       .
register_new_client() ->
    ClientCredentials = oauth1_credentials:generate(client),
    case oauth1_credentials:store(ClientCredentials)
    of  {ok, ok} ->
            Pair =
                { oauth1_credentials:get_id(ClientCredentials)
                , oauth1_credentials:get_secret(ClientCredentials)
                },
            {ok, Pair}
    ;   {error, _}=Error ->
            Error
    end.

%% @doc Initiate a resource access grant transaction.
%% @end
-spec initiate(args_initiate()) ->
    hope_result:t(Ok, Error)
    when Ok    :: {oauth1_credentials:t(tmp), CallbackConfirmed :: boolean()}
       , Error :: oauth1_storage:error()
                | error()
       .
initiate(#oauth1_server_args_initiate
    { resource            = Resource
    , consumer_key        = ConsumerKey
    , signature           = SigGiven
    , signature_method    = SigMethod = 'HMAC_SHA1'
    , timestamp           = Timestamp
    , nonce               = Nonce

    , client_callback_uri = CallbackURI

    , host                = Host
    }
) ->
    case oauth1_credentials:fetch(ConsumerKey)
    of  {error, not_found} ->
            {error, {unauthorized, client_credentials_invalid}}
    ;   {error, _}=Error ->
            Error
    ;   {ok, ClientCredentials} ->
            ClientSharedSecret =
                oauth1_credentials:get_secret(ClientCredentials),
            SigArgs =
                #oauth1_signature_args_cons
                { method               = SigMethod
                , http_req_method      = <<"POST">>
                , http_req_host        = Host
                , resource             = Resource
                , consumer_key         = ConsumerKey
                , timestamp            = Timestamp
                , nonce                = Nonce

                , client_shared_secret = ClientSharedSecret
                ,  token_shared_secret = none

                , token                = none
                , verifier             = none
                , callback             = {some, CallbackURI}
                },
            SigComputed       = oauth1_signature:cons(SigArgs),
            SigComputedDigest = oauth1_signature:get_digest(SigComputed),
            case SigGiven =:= SigComputedDigest
            of  false ->
                    {error, {unauthorized, signature_invalid}}
            ;   true  ->
                    case oauth1_nonce:fetch(Nonce)
                    of  {ok, ok} ->
                            {error, {unauthorized, nonce_used}}
                    ;   {error, not_found} ->
                            Token = oauth1_credentials:generate(tmp),
                            case oauth1_credentials:store(Token)
                            of  {error, _}=Error ->
                                    Error
                            ;   {ok, ok} ->
                                    TokenID = oauth1_credentials:get_id(Token),
                                    Callback =
                                        oauth1_callback:cons( TokenID
                                                            , CallbackURI
                                                            ),
                                    case oauth1_callback:store(Callback)
                                    of  {error, _}=Error ->
                                            Error
                                    ;   {ok, ok} ->
                                            IsCallbackConfirmed = false,
                                            {ok, {TokenID, IsCallbackConfirmed}}
                                    end
                            end
                    ;   {error, _}=Error ->
                            Error
                    end
            end
    end.

%% @doc Owner authorizes the client's temporary token and, in return, gets the
%% uri of the client "ready" callback with the tmp token and a verifier query
%% params.
%% @end
-spec authorize(TmpToken :: binary()) ->
    hope_result:t(Ok, Error)
    when Ok    :: oauth1_uri:t()
       , Error :: oauth1_storage:error()
                | error()
       .
authorize(<<TmpTokenID/binary>>) ->
    TmpToken = {tmp, TmpTokenID},
    case oauth1_credentials:fetch(TmpToken)
    of  {error, not_found} ->
            {error, {unauthorized, token_invalid}}
    ;   {error, _}=Error ->
            Error
    ;   {ok, _TmpCredentials} ->
            case oauth1_callback:fetch(TmpToken)
            of  {error, not_found} ->
                    error("No callback found for a valid tmp token!")
            ;   {error, _}=Error ->
                    Error
            ;   {ok, Callback1} ->
                    Verifier = oauth1_verifier:generate(TmpToken),
                    case oauth1_verifier:store(Verifier)
                    of  {error, _}=Error ->
                            Error
                    ;   {ok, ok} ->
                            Callback2 = oauth1_callback:set_verifier( Callback1
                                                                    , Verifier
                                                                    ),
                            oauth1_callback:get_uri(Callback2)
                    end
            end
    end.

%% @doc Grant the real access token.
%% @end
-spec token(args_token()) ->
    hope_result:t(Ok, Error)
    when Ok    :: oauth1_credentials:t(token)
       , Error :: oauth1_storage:error()
                | error()
       .
token(#oauth1_server_args_token
    { resource         = Resource
    , consumer_key     = {client, <<_/binary>>}=ConsumerKey
    , signature        = <<SigGiven/binary>>
    , signature_method = SigMethod = 'HMAC_SHA1'
    , timestamp        = Timestamp
    , nonce            = Nonce

    , temp_token       = {tmp, <<_/binary>>}=TmpToken
    , verifier         = <<VerifierGivenBin/binary>>

    , host             = Host
    }
) ->
    ValidateConsumerKey =
        fun (#request_validation_state{}=State1) ->
            case oauth1_credentials:fetch(ConsumerKey)
            of  {error, not_found} ->
                    {error, {unauthorized, client_credentials_invalid}}
            ;   {error, _}=Error ->
                    Error
            ;   {ok, ClientCredentials} ->
                    State2 =
                        State1#request_validation_state
                        { creds_client = {some, ClientCredentials}
                        },
                    {ok, State2}
            end
        end,
    ValidateTmpToken =
        fun (#request_validation_state{}=State1) ->
            case oauth1_credentials:fetch(TmpToken)
            of  {error, not_found} ->
                    {error, {unauthorized, token_invalid}}
            ;   {ok, TmpTokenCredentials} ->
                    State2 =
                        State1#request_validation_state
                        { creds_tmp = {some, TmpTokenCredentials}
                        },
                    {ok, State2}
            end
        end,
    ValidateVerifier =
        fun (#request_validation_state{}=State1) ->
            case oauth1_verifier:fetch(TmpToken)
            of  {error, not_found} ->
                    {error, {unauthorized, verifier_invalid}}
            ;   {ok, Verifier} ->
                    VerifierBin = oauth1_verifier:get_value(Verifier),
                    case VerifierGivenBin =:= VerifierBin
                    of  false ->
                            {error, {unauthorized, verifier_invalid}}
                    ;   true ->
                            State2 =
                                State1#request_validation_state
                                { verifier = {some, Verifier}
                                },
                            {ok, State2}
                    end
            end
        end,
    ValidateSignature =
        fun (#request_validation_state
            { creds_client = {some, ClientCredentials}
            , creds_tmp    = {some, TmpTokenCredentials}
            , verifier     = {some, Verifier}
            }=State) ->
            TmpTokenSharedSecret =
                oauth1_credentials:get_secret(TmpTokenCredentials),
            ClientSharedSecret =
                oauth1_credentials:get_secret(ClientCredentials),
            SigArgs =
                #oauth1_signature_args_cons
                { method               = SigMethod
                , http_req_method      = <<"POST">>
                , http_req_host        = Host
                , resource             = Resource
                , consumer_key         = ConsumerKey
                , timestamp            = Timestamp
                , nonce                = Nonce

                , client_shared_secret =          ClientSharedSecret
                ,  token_shared_secret = {some, TmpTokenSharedSecret}

                , token                = {some, TmpToken}
                , verifier             = {some, Verifier}
                , callback             = none
                },
            SigComputed       = oauth1_signature:cons(SigArgs),
            SigComputedDigest = oauth1_signature:get_digest(SigComputed),
            case SigGiven =:= SigComputedDigest
            of  false -> {error, {unauthorized, signature_invalid}}
            ;   true  -> {ok, State}
            end
        end,
    ValidateNonce =
        fun (#request_validation_state{}=State) ->
            case oauth1_nonce:fetch(Nonce)
            of  {ok, ok}           -> {error, {unauthorized, nonce_used}}
            ;   {error, not_found} -> {ok, State}
            end
        end,
    IssueToken =
        fun (#request_validation_state{}=State1) ->
            Token = oauth1_credentials:generate(token),
            case oauth1_credentials:store(Token)
            of  {error, _}=Error ->
                    Error
            ;   {ok, ok} ->
                    State2 =
                        State1#request_validation_state
                        { result = {some, Token}
                        },
                    {ok, State2}
            end
        end,
    Steps =
        [ ValidateConsumerKey
        , ValidateTmpToken
        , ValidateVerifier
        , ValidateSignature
        , ValidateNonce
        , IssueToken
        ],
    State1 = #request_validation_state{},
    State2 = hope_result:pipe(Steps, State1),
    {some, Token} = State2#request_validation_state.result,
    Token.

-spec validate_resource_request(args_validate_resource_request()) ->
    hope_result:t(ok, Error)
    when Error :: oauth1_storage:error()
                | error()
       .
validate_resource_request(#oauth1_server_args_validate_resource_request
    { realm            = _Realm
    , consumer_key     = _ConsumerKey
    , signature        = _Signature
    , signature_method = _SignatureMethod
    , timestamp        = _Timestamp
    , nonce            = _Nonce
    , token            = _Token
    }
) ->
    ?not_implemented.
