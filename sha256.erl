-module(sha256).
-export([hexdigest/1]).

hexdigest(Message) ->
  pad_message(Message).

pad_message(Message) ->
  lists:append(Message, extra_bytes(length(Message))).

extra_bytes(Len) ->
  lists:append([separator_byte(), pad_bytes(Len), len_bytes(Len)]).

separator_byte() ->
  [128].

pad_bytes(Len) ->
  lists:duplicate(64 - ((Len + 9) rem 64), 0).

len_bytes(Len) ->
  fill_with_zeros(binary_to_list(binary:encode_unsigned(Len * 8, big)), 8).

fill_with_zeros(List, Pad) ->
  lists:append([
    lists:duplicate(Pad - (length(List) rem Pad), 0),
    List
  ]).
