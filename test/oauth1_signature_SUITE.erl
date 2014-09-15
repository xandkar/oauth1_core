-module(oauth1_signature_SUITE).

-include_lib("oauth1_signature.hrl").

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_suite/1
    , init_per_group/2
    , end_per_group/2
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_key/1
    , t_base_string/1
    , t_digest/1
    ]).


-define(CASE_GROUP_HUENIVERSE_GUIDE, hueniverse_guide).
-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , crdt
    , oauth1_core
    ]).
-define(CFG_KEY_SIG                 , sig).
-define(CFG_KEY_SIG_KEY_EXPECTED    , sig_key_expected).
-define(CFG_KEY_SIG_TEXT_EXPECTED   , sig_text_expected).
-define(CFG_KEY_SIG_DIGEST_EXPECTED , sig_digest_expected).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?CASE_GROUP_HUENIVERSE_GUIDE}].

groups() ->
    [ spec_for_case_group_hueniverse_guide()
    ].

init_per_suite(Cfg) ->
    StartApp = fun (App) -> ok = application:start(App) end,
    ok = lists:foreach(StartApp, ?APP_DEPS),
    Cfg.

end_per_suite(_Cfg) ->
    StopApp = fun (App) -> ok = application:stop(App) end,
    ok = lists:foreach(StopApp, lists:reverse(?APP_DEPS)).

init_per_group(?CASE_GROUP_HUENIVERSE_GUIDE, Cfg1) ->
    % Test case based on:
    % https://web.archive.org/web/20131222062830/http://nouncer.com/oauth/signature.html
    Realm = <<"http://photos.example.net/photos">>,
    ResourceURIBin =
        <<"http://photos.example.net/photos?size=original&file=vacation.jpg">>,
    {ok, ResourceURI} = oauth1_uri:of_bin(ResourceURIBin),
    Resource = oauth1_resource:cons(Realm, ResourceURI),
    TokenIDBin = <<"nnch734d00sl2jdk">>,
    TokenSecretBin = <<"pfkkdhi9sl3r4s00">>,
    Token = oauth1_credentials:cons(token, TokenIDBin, TokenSecretBin),
    SigArgs = #oauth1_signature_args_cons
        { method               = 'HMAC_SHA1'
        , http_req_method      = <<"GET">>
        , http_req_host        = <<"photos.example.net">>
        , resource             = Resource
        , consumer_key         = {client, <<"dpf43f3p2l4k3l03">>}
        , timestamp            = 1191242096
        , nonce                = <<"kllo9940pd9333jh">>

        , client_shared_secret = {client, <<"kd94hf93k423kf44">>}

        , token                = {some, Token}
        , verifier             = none
        , callback             = none

        , version              = {some, '1.0'}
        },
    SigKeyExpected    = <<"kd94hf93k423kf44&pfkkdhi9sl3r4s00">>,
    SigTextExpected   = <<"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal">>,
    % We expect that parameter values (and thus the signature digest) be
    % url-encoded only duting serialization, by oauth1_parameters module.
    SigDigestExpected = cow_qs:urldecode(<<"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D">>),
    Sig = oauth1_signature:cons(SigArgs),
    Cfg2 = orddict:store(?CFG_KEY_SIG                , Sig              , Cfg1),
    Cfg3 = orddict:store(?CFG_KEY_SIG_KEY_EXPECTED   , SigKeyExpected   , Cfg2),
    Cfg4 = orddict:store(?CFG_KEY_SIG_TEXT_EXPECTED  , SigTextExpected  , Cfg3),
    Cfg5 = orddict:store(?CFG_KEY_SIG_DIGEST_EXPECTED, SigDigestExpected, Cfg4),
    Cfg5.

end_per_group(?CASE_GROUP_HUENIVERSE_GUIDE, _Cfg) ->
    ok.


%%=============================================================================
%% Tests
%%=============================================================================

t_key(Cfg) ->
    {some, Sig}         = kvl_find(Cfg, ?CFG_KEY_SIG),
    {some, KeyExpected} = kvl_find(Cfg, ?CFG_KEY_SIG_KEY_EXPECTED),
    KeyComputed = oauth1_signature:get_key(Sig),
    ct:log("KeyExpected: ~p", [KeyExpected]),
    ct:log("KeyComputed: ~p", [KeyComputed]),
    KeyComputed = KeyExpected.

t_base_string(Cfg) ->
    {some, Sig}                = kvl_find(Cfg, ?CFG_KEY_SIG),
    {some, BaseStringExpected} = kvl_find(Cfg, ?CFG_KEY_SIG_TEXT_EXPECTED),
    BaseStringComputed = oauth1_signature:get_text(Sig),
    ct:log("BaseStringExpected: ~p", [BaseStringExpected]),
    ct:log("BaseStringComputed: ~p", [BaseStringComputed]),
    BaseStringComputed = BaseStringExpected.

t_digest(Cfg) ->
    {some, Sig}               = kvl_find(Cfg, ?CFG_KEY_SIG),
    {some, SigDigestExpected} = kvl_find(Cfg, ?CFG_KEY_SIG_DIGEST_EXPECTED),
    SigDigestComputed = oauth1_signature:get_digest(Sig),
    ct:log("SigDigestExpected: ~p", [SigDigestExpected]),
    ct:log("SigDigestComputed: ~p", [SigDigestComputed]),
    SigDigestExpected = SigDigestComputed,
    ok.


%%=============================================================================
%% Helpers
%%=============================================================================

kvl_find(L, K) ->
    case lists:keysearch(K, 1, L)
    of  false           -> none
    ;   {value, {K, V}} -> {some, V}
    end.

spec_for_case_group_hueniverse_guide() ->
    Tests =
        [ t_key
        , t_base_string
        , t_digest
        ],
    Properties = [],
    {?CASE_GROUP_HUENIVERSE_GUIDE, Properties, Tests}.
