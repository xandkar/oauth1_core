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
    [ t_hueniverse_guide_key/1
    , t_hueniverse_guide_base_string/1
    , t_hueniverse_guide_digest/1
    ]).


-define(GROUP_HUENIVERSE_GUIDE, case_hueniverse_guide).
-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1
    ]).
-define(STATE_KEY_SIG, sig).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP_HUENIVERSE_GUIDE}].

groups() ->
    [ group_hueniverse_guide()
    ].

init_per_suite(Config) ->
    StartApp = fun (App) -> ok = application:start(App) end,
    ok = lists:foreach(StartApp, ?APP_DEPS),
    Config.

end_per_suite(_Config) ->
    StopApp = fun (App) -> ok = application:stop(App) end,
    ok = lists:foreach(StopApp, lists:reverse(?APP_DEPS)).

init_per_group(?GROUP_HUENIVERSE_GUIDE, Config) ->
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
        },
    Sig = oauth1_signature:cons(SigArgs),
    orddict:store(?STATE_KEY_SIG, Sig, Config).

end_per_group(?GROUP_HUENIVERSE_GUIDE, _Config) ->
    ok.


%%=============================================================================
%% Tests
%%=============================================================================

t_hueniverse_guide_key(Config) ->
    {some, Sig} = kvl_find(Config, ?STATE_KEY_SIG),
    KeyExpected = <<"kd94hf93k423kf44&pfkkdhi9sl3r4s00">>,
    KeyComputed = oauth1_signature:get_key(Sig),
    KeyComputed = KeyExpected.

t_hueniverse_guide_base_string(Config) ->
    {some, Sig} = kvl_find(Config, ?STATE_KEY_SIG),
    BaseStringExpected = <<"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal">>,
    BaseStringComputed = oauth1_signature:get_text(Sig),
    ct:log("BaseStringExpected: ~p", [BaseStringExpected]),
    ct:log("BaseStringComputed: ~p", [BaseStringComputed]),
    BaseStringComputed = BaseStringExpected.

t_hueniverse_guide_digest(Config) ->
    {some, Sig} = kvl_find(Config, ?STATE_KEY_SIG),
    SigDigestExpected = <<"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D">>,
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

group_hueniverse_guide() ->
    Tests =
        [ t_hueniverse_guide_key
        , t_hueniverse_guide_base_string
        , t_hueniverse_guide_digest
        ],
    Properties = [],
    {?GROUP_HUENIVERSE_GUIDE, Properties, Tests}.
