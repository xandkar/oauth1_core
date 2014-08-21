-module(oauth1_credentials_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_group/2
    , end_per_group/2
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Test cases
-export(
    [ t_generate_and_store/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(TYPE  , type).
-define(CREDS , creds).

-define(TYPE_CLIENT , client).
-define(TYPE_TMP    , tmp).
-define(TYPE_TOKEN  , token).


%% ============================================================================
%% Common Test callbacks
%% ============================================================================

all() ->
    [ {group, ?TYPE_CLIENT}
    , {group, ?TYPE_TMP}
    , {group, ?TYPE_TOKEN}
    ].

groups() ->
    Tests =
        [ t_generate_and_store
        % TODO: Error cases:
        %   - string generation error (low entropy)
        %   - storage errors
        %   - invalid data format upon retrival from storage
        ],
    Properties = [],
    [ {?TYPE_CLIENT , Properties, Tests}
    , {?TYPE_TMP    , Properties, Tests}
    , {?TYPE_TOKEN  , Properties, Tests}
    ].

init_per_group(Type, Cfg) ->
    hope_kv_list:set(Cfg, ?TYPE, Type).

end_per_group(_DictModule, _Cfg) ->
    ok.

init_per_suite(Cfg) ->
    StartApp = fun (App) -> ok = application:start(App) end,
    ok = lists:foreach(StartApp, ?APP_DEPS),
    Cfg.

end_per_suite(_Cfg) ->
    StopApp = fun (App) -> ok = application:stop(App) end,
    ok = lists:foreach(StopApp, lists:reverse(?APP_DEPS)).


%% =============================================================================
%%  Test cases
%% =============================================================================

t_generate_and_store(Cfg1) ->
    {some, Type} = hope_kv_list:get(Cfg1, ?TYPE),

    {ok, Creds1} = oauth1_credentials:generate_and_store(Type),
    ID1          = oauth1_credentials:get_id(Creds1),
    Secret1      = oauth1_credentials:get_secret(Creds1),

    {ok, Creds2} = oauth1_credentials:fetch(ID1),
    ID2          = oauth1_credentials:get_id(Creds2),
    Secret2      = oauth1_credentials:get_secret(Creds2),

    ID1          = ID2,
    Secret1      = Secret2,
    Creds1       = Creds2.
