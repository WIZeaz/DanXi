/*
 *     Copyright (C) 2021  DanXi-Dev
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import 'package:shared_preferences/shared_preferences.dart';

/// A helper class to cache data locally and load it remotely if necessary.
class Cache {
  /// Get a cached data.
  ///
  /// Look for data with [key] and [decode] it to the specific type,
  /// if [key] is not found, or the data is null, or we don't [validate] it,
  /// [fetch] it from remote (usually from network), [encode] it and save it locally.
  ///
  /// Finally, return the cached data.
  static Future<T> get<T>(String key, Future<T> fetch(),
      T decode(String? cachedValue), String encode(T object),
      {bool validate(String cachedValue)?}) async {
    SharedPreferences preferences = await SharedPreferences.getInstance();
    if (validate == null) {
      validate = (v) => v != null;
    }
    if (!preferences.containsKey(key)) {
      // Reload the cache
      T newValue = await fetch();
      if (validate(encode(newValue)))
        preferences.setString(key, encode(newValue));
      return newValue;
    }
    String? result = preferences.getString(key);
    if (validate(result!)) {
      return decode(result);
    } else {
      T newValue = await fetch();
      preferences.setString(key, encode(newValue));
      return newValue;
    }
  }

  /// Get a cached data.
  ///
  /// But network goes first.
  static Future<T> getRemotely<T>(String key, Future<T> fetch(),
      T decode(String? cachedValue), String encode(T object),
      {bool validate(T value)?}) async {
    SharedPreferences preferences = await SharedPreferences.getInstance();
    if (validate == null) {
      validate = (v) => v != null;
    }
    T newValue = await fetch();
    if (validate(newValue)) {
      preferences.setString(key, encode(newValue));
      return newValue;
    } else {
      // Fall back to local cache.
      return get(key, fetch, decode, encode,
          validate: (v) => v != null && validate!(decode(v)));
    }
  }
}
