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

import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:dan_xi/model/person.dart';
import 'package:dan_xi/repository/inpersistent_cookie_manager.dart';
import 'package:dan_xi/repository/uis_login_tool.dart';
import 'package:dan_xi/util/bmob/bmob/realtime/client.dart';
import 'package:dan_xi/util/dio_utils.dart';
import 'package:dio/adapter.dart';
import 'package:dio/dio.dart';
import 'package:dan_xi/util/encrypt_utils.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:dio_log/interceptor/dio_log_interceptor.dart';
import 'package:flutter/material.dart';

class WebVPNInterceptor extends Interceptor {
  static const String WEBVPN_HOST = "webvpn.fudan.edu.cn";
  static const String WEBVPN_BASE_URL = "https://webvpn.fudan.edu.cn/";
  static Dio _login_dio = Dio();
  static NonpersistentCookieJar cookieJar = NonpersistentCookieJar();
  final NonpersistentCookieJar realJar;

  WebVPNInterceptor(this.realJar);

  static Future<void> init(PersonInfo info) async {
    _login_dio.interceptors.add(CookieManager(cookieJar));
    _login_dio.interceptors.add(DioLogInterceptor());
    (_login_dio.httpClientAdapter as DefaultHttpClientAdapter)
        .onHttpClientCreate = (client) {
      client.badCertificateCallback = (cert, host, port) {
        return true;
      };
    };
    var req = await UISLoginTool.loginWebVpn(_login_dio, cookieJar, info);
    print("reqed!");
  }

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (options.uri.host != WEBVPN_HOST) {
      options.path = WEBVPN_BASE_URL + encryptUri(options.uri);
      options.headers.update("host", (value) => "webvpn.fudan.edu.cn",
          ifAbsent: () => "webvpn.fudan.edu.cn");
    }
    print(options.uri.toString());
    options.followRedirects = false;
    options.validateStatus = (status) {
      return status < 400;
    };
    processRequest(options, handler);
  }

  void processRequest(
      RequestOptions options, RequestInterceptorHandler handler) {
    Function errorHandler = (e) => handler.reject(e, true);
    _login_dio.fetch(options).then(
        (value) => DioUtils.processRedirect(_login_dio, value).then(
            (value) => handler.resolve(value, true),
            onError: errorHandler),
        onError: errorHandler);
  }

  void affixCookie(NonpersistentCookieJar cookieJarFrom,
      NonpersistentCookieJar cookieJarTo) {
    cookieJarFrom.hostCookies.forEach((host, value) {
      value.forEach((path, value) {
        cookieJarTo.saveFromResponse(Uri(host: host, path: path),
            value.values.map((e) => e.cookie).toList());
      });
    });
    cookieJarFrom.domainCookies.forEach((host, value) {
      value.forEach((path, value) {
        cookieJarTo.saveFromResponse(Uri(host: host, path: path),
            value.values.map((e) => e.cookie).toList());
      });
    });
  }

  static String encryptUri(Uri uri) {
    var result = uri.scheme + '/' + encryptHost(uri.host);
    if (!uri.path.isNullOrEmpty) result += uri.path;
    if (!uri.query.isNullOrEmpty) result += '?' + uri.query;
    return result;
  }

  static String encryptHost(String host) {
    int originLength = host.length;
    const segmentByteSize = 16;
    Uint8List key = 'wrdvpnisthebest!'.toUtf8Bytes();
    int appendLength = segmentByteSize - originLength % segmentByteSize;
    int i = 0;
    while (i++ < appendLength) {
      host += '0';
    }

    AesCrypt crypt = AesCrypt();
    crypt.aesSetParams(key, key, AesMode.cfb);
    Uint8List encryptBytes = crypt.aesEncrypt(host.toUtf8Bytes());
    return key.toHexString().toLowerCase() +
        encryptBytes.toHexString().toLowerCase().substring(0, originLength * 2);
  }
}
