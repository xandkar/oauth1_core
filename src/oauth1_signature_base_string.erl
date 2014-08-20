-module(oauth1_signature_base_string).

-include_lib("oauth1_module_abbreviations.hrl").
-include_lib("oauth1_signature_base_string.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-type t() ::
    binary().

-type args_cons() ::
    #oauth1_signature_base_string_args_cons{}.


-define(AMPERSAND, "&").


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_base_string_args_cons
    { signature_method = 'HMAC_SHA1'
    , http_req_method  = HttpMeth
    , http_req_host    = _HttpHost
    , resource         = Resource
    , consumer_key     = ConsumerKey
    , timestamp        = Timestamp
    , nonce            = Nonce

    , token_id         = TokenIDOpt
    , verifier         = VerifierOpt
    , callback         = CallbackOpt

    , version          = VersionOpt
    }
) ->
    URI           = ?resource:get_uri(Resource),
    BaseStringURI = ?signature_base_string_uri:cons(URI),
    TokenPair =
        case TokenIDOpt
        of  none                      -> []
        ;   {some, {tmp  , TokenBin}} -> [{<<"oauth_token">>, TokenBin}]
        ;   {some, {token, TokenBin}} -> [{<<"oauth_token">>, TokenBin}]
        end,
    VerifierPair =
        case VerifierOpt
        of  none ->
                []
        ;   {some, Verifier} ->
                VerifierBin = ?verifier:get_value(Verifier),
                [{<<"oauth_verifier">>, VerifierBin}]
        end,
    CallbackPair =
        case CallbackOpt
        of  none ->
                []
        ;   {some, Callback} ->
                CallbackBin = ?signature_base_string_uri:cons(Callback),
                [{<<"oauth_callback">>, CallbackBin}]
        end,
    VersionPair =
        case VersionOpt
        of  {some, '1.0'} -> [{<<"oauth_version">>, <<"1.0">>}]
        ;   none          -> []
        end,
    QueryPairs = ?uri:get_query(URI),
    ParameterPairs =
        [ {<<"oauth_signature_method">> , <<"HMAC-SHA1">>}
        , {<<"oauth_consumer_key">>     , ?credentials:id_to_bin(ConsumerKey)}
        , {<<"oauth_timestamp">>        , ?timestamp:to_bin(Timestamp)}
        , {<<"oauth_nonce">>            , Nonce}
        | QueryPairs
        ]
        ++ VersionPair
        ++ TokenPair
        ++ VerifierPair
        ++ CallbackPair,
    ParameterPairsEncoded =
        [{encode(K), encode(V)}|| {K, V} <- ParameterPairs],
    ParameterSortComparator =
        fun ({K , V1}, {K , V2}) -> V1 =< V2
        ;   ({K1,  _}, {K2,  _}) -> K1 =< K2
        end,
    ParameterPairsSorted =
        lists:usort(ParameterSortComparator, ParameterPairsEncoded),
    ParametersString =
        case ParameterPairsSorted
        of  [] ->
                <<>>
        ;   [{K1, V1} | Pairs] ->
                ParameterAppend =
                    fun ({K, V}, Acc) ->
                        <<Acc/binary, "&", K/binary, "=", V/binary>>
                    end,
                String1 = <<K1/binary, "=", V1/binary>>,
                String2 = lists:foldl(ParameterAppend, String1, Pairs),
                encode(String2)
        end,
    % TODO: ParametersFromHttpEntityBody = ... ,
    %
    << HttpMeth/binary
    ,  ?AMPERSAND
    ,  BaseStringURI/binary
    , ?AMPERSAND
    ,  ParametersString/binary
    >>.


-spec encode(binary()) ->
    binary().
encode(<<String/binary>>) ->
    cow_qs:urlencode(String).
