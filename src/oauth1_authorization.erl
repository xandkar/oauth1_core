-module(oauth1_authorization).

-export_type(
    [ t/0
    ]).

-export(
    % Construct
    [ cons/1

    % Access
    , add/2
    , remove/2
    , is_authorized/2

    % Persist
    , store/1
    , fetch/1
    ]).


-type token() ::
    oauth1_credentials:id(token).

-type resource() ::
    oauth1_resource:t().

-record(t,
    { token     :: token()
    % TODO: Are we authorizing resources or realms?
    , resources :: [resource()]
    }).

-opaque t() ::
    #t{}.


% TODO: All bucket names should be defined at app config.
-define(STORAGE_BUCKET_NAME, <<"oauth1-authorizations">>).


-spec cons(token()) ->
    t().
cons({token, <<_/binary>>}=Token) ->
    #t
    { token     = Token
    , resources = ordsets:new()
    }.

-spec add(t(), resource()) ->
    t().
add(#t{resources=Resources}=T, Resource) ->
    T#t
    { resources = ordsets:add_element(Resource, Resources)
    }.

-spec remove(t(), resource()) ->
    t().
remove(#t{resources=Resources}=T, Resource) ->
    T#t
    { resources = ordsets:del_element(Resource, Resources)
    }.

-spec is_authorized(t(), resource()) ->
    boolean().
is_authorized(#t{resources=Resources}, Resource) ->
    ordsets:is_element(Resource, Resources).

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t
    { token     = {token, <<Token/binary>>}
    , resources = Resources
    }
) ->
    ResourcesProps = lists:map(fun oauth1_resource:to_props/1, Resources),
    ResourcesJson  = jsx:encode(ResourcesProps),
    Key   = Token,
    Value = ResourcesJson,
    oauth1_storage:put(?STORAGE_BUCKET_NAME, Key, Value).

-spec fetch(token()) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch({token, <<TokenID/binary>>}=Token) ->
    Key = TokenID,
    case oauth1_storage:get(?STORAGE_BUCKET_NAME, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, ResourcesJson} ->
            ResourcesProps = jsx:decode(ResourcesJson),
            Resources      = lists:map( fun oauth1_resource:of_props/1
                                      , ResourcesProps
                                      ),
            T = #t
                { token     = Token
                , resources = Resources
                },
            {ok, T}
    end.
