%% -*- coding: utf-8 -*-
-module(unifi).
-author("Andrey Andruschenko <apofiget@gmail.com>").

-export([login/3, login/5, logout/1, backup/1, 
         get_alerts/1, get_alerts_unarchived/1, get_events/1,
         get_events/2, get_aps/1, get_alluser/3,
         get_alluser_offline/3, get_users/1, get_users_active/1,
         get_user_groups/1, get_wlans/1, get_settings/1,
         block_client/2, unblock_client/2, disconnect_client/2,
         restart_ap/2, archive_alerts/1, auth_guest/3,
         auth_guest/5, auth_guest/6, unauth_guest/2,
         gen_voucher/3, gen_voucher/5, gen_voucher/6,
         gen_voucher_ot/3, gen_voucher_ot/5, gen_voucher_ot/6,
         get_voucher/2, del_voucher/2]).

%% UniFi controller API, tested with v2.4.6
%% UniFi FAQ: http://wiki.ubnt.com/UniFi_FAQ, 
%% Community KB: http://community.ubnt.com/t5/tkb/communitypage
%% UniFi Controller: http://www.ubnt.com/download/?group=unifi-ap

%% Type of controller client
-type user_type() :: all | guest | user | noted | blocked.
-type version() :: v2 | v3.
-type opt_list() :: [option()].
-type option() :: {url, Url :: string()} | {cookie, Cookie :: string()} | {path, Path :: string()}.

%% Open session. Return session cookie or error.
%% Use it first before send other request.
%% For UniFi controller v3: Version and Site needed, default site name - "default"
%% For v2 API only
-spec(login(Url :: string, Login :: string(), Pass :: string()) -> {ok, opt_list()} | {error, Reply :: string()}).
login(Url, Login, Pass) -> login(Url, Login, Pass, v2, "").
%% For v2/v3 API
-spec(login(Url :: string, Login :: string(), Pass :: string(), Version :: version(), Site :: string()) -> {ok, opt_list()} | {error, Reply :: string()}).
login(Url, Login, Pass, Version, Site) ->
    try [ok,ok,ok,ok,ok] = [application:ensure_started(A) || A <- [asn1, crypto, public_key, ssl, ibrowse]] of
        _ ->
            Path = case Version of
                       v3 -> "api/s/" ++ Site ++ "/";
                       _ -> "api/"
                   end,
            case ibrowse:send_req(Url ++ "login", [{"Content-Type", "application/x-www-form-urlencoded"}], post, "login=Login&username="++Login++"&password="++Pass, conn_opts()) of
                {error, Reason} -> {error, Reason};
                {ok, "302",Headers, _} -> {ok, [{url, Url}, {cookie, string:strip(hd(string:tokens(proplists:get_value("Set-Cookie", Headers), " ")), right, $;)}, {path, Path}]};
                {ok, "200", _, _} -> {error, "Login failed"};
                {ok, _, _, Body} -> {error, Body}
            end
    catch _:_ ->
            {error, "Some dependence application not stated"}
    end.

%% Close session.
-spec(logout(Opts :: opt_list()) -> ok | {error, Reply :: string()}).
logout(Opts) ->
    case ibrowse:send_req(proplists:get_value(url, Opts) ++ "logout", [{cookie, proplists:get_value(cookie, Opts)}], get, [], conn_opts()) of
        {ok, "302", _, _} -> ok;
        {ok, _, _, Body} -> {error, Body};
        {error, Reason} -> {error, Reason}
    end.

%% Return backup of controller configuration
-spec(backup(Opts :: opt_list()) -> {ok, File :: binary()} | {error, Reply :: string()}).
backup(Opts) ->
    case ibrowse:send_req(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/system", [{"Content-Type", "application/x-www-form-urlencoded"}, {cookie, proplists:get_value(cookie, Opts)}], post, <<"json={'cmd':'backup'}">> , conn_opts()) of
        {ok, "200", Headers, Body} ->
            case proplists:get_value("Content-Type", Headers) of
                "application/json" -> R = parse_json_obj(Body),
                                      case R of
                                          {ok, Obj} ->
                                              DlUrl = proplists:get_value("url", Obj),
                                              DlReply = ibrowse:send_req(proplists:get_value(url, Opts) ++ string:strip(DlUrl, left, $/), [{cookie, proplists:get_value(cookie, Opts)}], get, [], [ {response_format, binary}| conn_opts()]),
                                              case DlReply of
                                                  {ok, "200", _, File} -> {ok, File};
                                                  {ok, _, _, Reply} -> {error, Reply};
                                                  Any -> Any
                                              end;
                                          Any -> Any
                                      end;
                    _ -> {error, Body}
            end;
        {ok, "302", _, _} -> {error, "Authorization required!"};
        {ok, _, _, Body} -> {error, Body};
        Any -> Any
    end.

%% Return list of unarchived alers
-spec(get_alerts_unarchived(Opts :: opt_list()) -> {ok, [Alers :: list()]} | {error, Reply :: string()}).
get_alerts_unarchived(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/alarm", proplists:get_value(cookie, Opts), <<"json={'_sort':'-time','archived':false}">>).

%% Return list of all alerts
-spec(get_alerts(Opts :: opt_list()) -> {ok, [Alers :: list()]} | {error, Reply :: string()}).
get_alerts(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/alarm", proplists:get_value(cookie, Opts), <<"json={'_sort':'-time'}">>).

%% Archive active alerts
-spec(archive_alerts(Opts :: opt_list()) -> {ok, [none]} | {error, Reply :: string()}).
archive_alerts(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/evtmgr", proplists:get_value(cookie, Opts), <<"json={'cmd':'archive-all-alarms'}">>).

%% Return list of all events
-spec(get_events(Opts :: opt_list()) -> {ok, [Events :: list()]} | {error, Reply :: string()}).
get_events(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/event", proplists:get_value(cookie, Opts), <<>>).

%% Return list of all events within N hours
-spec(get_events(Opts :: opt_list(), Hours :: integer()) -> {ok, [Events :: list()]} | {error, Reply :: string()}).
get_events(Opts, Hours) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/event", proplists:get_value(cookie, Opts), list_to_binary("json={'within':'" ++ integer_to_list(Hours) ++ "'}")).

%% Return list of AP's with options
-spec(get_aps(Opts :: opt_list()) -> {ok, [Ap :: list()]} | {error, Reply :: string()}).
get_aps(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/device", proplists:get_value(cookie, Opts), <<"json={'_depth': 1, 'test': null}">>).

%% Return a list of all known clients, with detailed information about each.
-spec(get_alluser(Opts :: opt_list(), Type :: user_type(), Hours :: integer()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_alluser(Opts, Type, Hours) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/alluser", proplists:get_value(cookie, Opts), list_to_binary("json={'type':'"++ atom_to_list(Type) ++"','is_offline':false,'within':'"++ integer_to_list(Hours) ++"'}")).

%% Return a list of all known offline clients, with detailed information about each.
-spec(get_alluser_offline(Opts :: opt_list(), Type :: user_type(), Hours :: integer()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_alluser_offline(Opts, Type, Hours) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/alluser", proplists:get_value(cookie, Opts), list_to_binary("json={'type':'"++ atom_to_list(Type) ++"','is_offline':true,'within':'"++ integer_to_list(Hours) ++"'}")).

%% Return a list of all known clients, with significant information about each.
-spec(get_users(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_users(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/user", proplists:get_value(cookie, Opts), <<"json={}">>).

%% Return a list of all active clients, with significant information about each.
-spec(get_users_active(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_users_active(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/sta", proplists:get_value(cookie, Opts), <<"json={}">>).

%% Return a list of user groups with its settings.
-spec(get_user_groups(Opts :: opt_list()) -> {ok, [User :: list()]} | {error, Reply :: string()}).
get_user_groups(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/usergroup", proplists:get_value(cookie, Opts), <<"json={}">>).

%% Return a list of wireless networks with settings.
-spec(get_wlans(Opts :: opt_list()) -> {ok, [Wlan :: list()]} | {error, Reply :: string()}).
get_wlans(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/wlanconf", proplists:get_value(cookie, Opts), <<"json={}">>).

%% Return a list of controller settings.
-spec(get_settings(Opts :: opt_list()) -> {ok, [Option :: list()]} | {error, Reply :: string()}).
get_settings(Opts) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "list/setting", proplists:get_value(cookie, Opts), <<"json={}">>).

%% Block wireless client with given MAC-address
-spec(block_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
block_client(Opts, Mac) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'block-sta', 'mac':'"++ Mac ++"'}")).

%% Unblock wireless client with given MAC-address
-spec(unblock_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
unblock_client(Opts, Mac) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'unblock-sta', 'mac':'"++ Mac ++"'}")).

%% Disconnect wireless client with given MAC-address, forcing them to reassociate.
-spec(disconnect_client(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
disconnect_client(Opts, Mac) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'kick-sta', 'mac':'"++ Mac ++"'}")).

%% Restart AP with given MAC-address.
-spec(restart_ap(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
restart_ap(Opts, Mac) ->
    get_array(proplists:get_value(url, Opts) ++  proplists:get_value(path, Opts) ++ "cmd/devmgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'restart', 'mac':'"++ Mac ++"'}")).

%% Authorize guest based on his MAC address.
%%   Mac     -- the guest MAC address: aa:bb:cc:dd:ee:ff
%%   Minutes -- duration of the authorization in minutes
%%   Up      -- up speed allowed in kbps (optional)
%%   Down    -- down speed allowed in kbps (optional)
%%   Quota   -- quantity of bytes allowed in MB (optional)
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'authorize-guest', 'mac':'" ++ Mac ++ "','minutes':" ++ integer_to_list(Minutes) ++ "}")).

%% + up/down bandwith limit
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer(), Up :: integer(), Down :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes, Up, Down) ->
    get_array(proplists:get_value(url, Opts) ++  proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'authorize-guest', 'mac':'" ++ Mac ++ 
                                                                  "','minutes':" ++ integer_to_list(Minutes) ++ ",'up':" ++ integer_to_list(Up) ++ 
                                                                  ",'down':" ++ integer_to_list(Down) ++ "}")).

%% + download quota
-spec(auth_guest(Opts :: opt_list(), Mac :: string(), Minutes :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, [null]} | {error, Reply :: string()}).
auth_guest(Opts, Mac, Minutes, Up, Down, Quota) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'authorize-guest', 'mac':'" ++ Mac ++ 
                                                                  "','minutes':" ++ integer_to_list(Minutes) ++ ",'up':" ++ integer_to_list(Up) ++ 
                                                                  ",'down':" ++ integer_to_list(Down) ++ 
                                                                  ",'bytes':" ++ integer_to_list(Quota) ++ "}")).
%% Unauthorize guest based on his MAC address.
-spec(unauth_guest(Opts :: opt_list(), Mac :: string()) -> {ok, [null]} | {error, Reply :: string()}).
unauth_guest(Opts, Mac) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/stamgr", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'unauthorize-guest', 'mac':'" ++ Mac ++ "'}")).

%% Vouchers/Hotspot API
%% Generate voucher(s)
%% Expires -- Minutes to voucher expires
%% Count   -- count vouchers to generate
%% Up      -- upload bandwith, kbps
%% Down    -- download bandwith, kbps
%% Quota   -- download quota, MB
%% OneTime -- one time use: 1 or 0
%% Return token: create_time
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'quota': 0}")).

%% + up/down bandwith limit
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count, Up, Down) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++ integer_to_list(Down) ++ ",'quota': 0}")).

%% + download quota
-spec(gen_voucher(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher(Opts, Expires, Count, Up, Down, Quota) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++ integer_to_list(Down) ++ ",'bytes':" ++ integer_to_list(Quota) ++ ",'quota': 0}")).

%% Same as above but for one time use vouchers generate
%%
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'quota': 1}")).

%% + up/down bandwith limit
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count, Up, Down) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++ integer_to_list(Down) ++ ",'quota': 1}")).

%% + download quota
-spec(gen_voucher_ot(Opts :: opt_list(), Expires :: integer(), Count :: integer(), Up :: integer(), Down :: integer(), Quota :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
gen_voucher_ot(Opts, Expires, Count, Up, Down, Quota) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'create-voucher','expire':" ++ integer_to_list(Expires) ++",'n':" ++ integer_to_list(Count) ++ ",'up':" ++ integer_to_list(Up) ++ ",'down':" ++ integer_to_list(Down) ++ ",'bytes':" ++ integer_to_list(Quota) ++ ",'quota': 1}")).

%% Return generated voucher(s)
-spec(get_voucher(Opts :: opt_list(), Token :: integer()) -> {ok, [tuple()]} | {error, Reply :: string()}).
get_voucher(Opts, Token) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "stat/voucher", proplists:get_value(cookie, Opts), list_to_binary("json={'create_time':" ++ integer_to_list(Token) ++ "}")).

%% Delete generated voucher
-spec(del_voucher(Opts :: opt_list(), Id :: string()) -> {ok, [none]} | {error, Reply :: string()}).
del_voucher(Opts, Id) ->
    get_array(proplists:get_value(url, Opts) ++ proplists:get_value(path, Opts) ++ "cmd/hotspot", proplists:get_value(cookie, Opts), list_to_binary("json={'cmd':'delete-voucher','_id':'" ++ Id ++ "'}")).

%% Get JSON from application service
%% @hidden
get_array(Url, Cookie, Request) ->
    case ibrowse:send_req(Url, [{"Content-Type", "application/x-www-form-urlencoded"},{cookie, Cookie}], post, Request, conn_opts()) of
        {ok, "200", Headers, Body} -> 
            case proplists:get_value("Content-Type", Headers) of
                "application/json" -> parse_json_obj(Body);
                Any -> Any
            end;
        Any -> Any
    end.

%% SSL connection options: only crypt connection, 
%% peer certificate verifycation always success
%% @hidden
conn_opts() ->
    [{is_ssl, true}, {ssl_options,[{versions,[tlsv1]}, {verify, verify_peer}, 
     {verify_fun,{fun(_,{_, _}, UserState) -> {valid, UserState} end, []}},
     {secure_renegotiate, true}, {depth, 4}, {fail_if_no_peer_cert, false}]}].

%% Deserialize JSON representation to Erlang proplist
%% @hidden
json2proplist(List) when is_list(List) ->
    lists:map(fun({Name, {struct, E}}) -> {Name, E}; 
               ({Name, {array, [{struct, E}]}}) -> {Name, E}; 
               ({Name, {array, E}}) -> {Name, E};
               ({Name, [{struct,E}]}) -> {Name, E};
               ({struct, L}) -> L;
               (E) -> E end , List);
json2proplist(E) -> E.


%% Decode and parse JSON reply
%% @hidden
parse_json_obj(Json) ->
    case json2:decode_string(Json) of
        {ok, {struct, Struct}} ->
            {struct,Meta} = proplists:get_value("meta", Struct),
            ReplyCode = proplists:get_value("rc", Meta),
            if ReplyCode =:= "ok" ->
               case proplists:get_value("data", Struct) of
                  {array,[{struct, Array}]} -> {ok, [{K,json2proplist(V)} || {K,V} <- json2proplist(Array)]};
                  {array,Structs} -> {ok, [ json2proplist(L)|| L <- json2proplist(Structs)]}
               end;
               true ->
                    {error, proplists:get_value("msg", Meta)}
            end;
        Any -> {error, Any}
    end.
