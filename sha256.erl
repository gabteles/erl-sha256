-module(sha256).
-export([hexdigest/1]).

hexdigest(Message) ->
  chunk_message(pad_message(Message)).

%% ---------------------------------------------
%% MESSAGE PADDING
%% ---------------------------------------------

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

%% ---------------------------------------------
%% MESSAGE CHUNKING
%% ---------------------------------------------

chunk_message(Message) ->
  slice_16(byte_list_to_word_list(Message)).

byte_list_to_word_list(ByteList) ->
  byte_list_to_word_list([], ByteList).

byte_list_to_word_list(WordList, []) ->
  WordList;
byte_list_to_word_list(WordList, [B1, B2, B3, B4 | ByteList]) ->
  byte_list_to_word_list(WordList ++ [bytes_to_word(B1, B2, B3, B4)], ByteList).

bytes_to_word(A,B,C,D) ->
  (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

slice_16(UnslicedList) ->
  slice_16([], UnslicedList).

slice_16(SlicedList, []) ->
  SlicedList;
slice_16(SlicedList, [A,B,C,D, E,F,G,H, I,J,K,L, M,N,O,P | WordList]) ->
  slice_16(SlicedList ++ [[A,B,C,D, E,F,G,H, I,J,K,L, M,N,O,P]], WordList).
