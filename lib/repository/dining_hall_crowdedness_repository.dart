import 'dart:convert';

import 'package:dan_xi/model/person.dart';
import 'package:dan_xi/public_extension_methods.dart';
import 'package:dan_xi/repository/inpersistent_cookie_manager.dart';
import 'package:dan_xi/repository/uis_login_tool.dart';
import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';

class DiningHallCrowdednessRepository {
  Dio _dio = Dio();
  NonpersistentCookieJar _cookieJar = NonpersistentCookieJar();
  static const String LOGIN_URL =
      "https://uis.fudan.edu.cn/authserver/login?service=https%3A%2F%2Fmy.fudan.edu.cn%2Fsimple_list%2Fstqk";
  static const String DETAIL_URL = "https://my.fudan.edu.cn/simple_list/stqk";

  DiningHallCrowdednessRepository._() {
    _dio.interceptors.add(CookieManager(_cookieJar));
  }

  static final _instance = DiningHallCrowdednessRepository._();

  factory DiningHallCrowdednessRepository.getInstance() => _instance;

  Future<Map<String, TrafficInfo>> getCrowdednessInfo(
      PersonInfo info, int areaCode) async {
    var result = Map<String, TrafficInfo>();
    await UISLoginTool.loginUIS(_dio, LOGIN_URL, _cookieJar, info);
    var response = await _dio.get(DETAIL_URL);

    //If it's not time for a meal
    if (response.data.toString().contains("仅")) {
      throw UnsuitableTimeException();
    }
    var dataString =
        response.data.toString().between("}", "</script>", headGreedy: false);
    var jsonExtraction = new RegExp(r'\[.+\]').allMatches(dataString);
    List names = jsonDecode(
        jsonExtraction.elementAt(areaCode * 3).group(0).replaceAll("\'", "\""));
    List cur = jsonDecode(jsonExtraction
        .elementAt(areaCode * 3 + 1)
        .group(0)
        .replaceAll("\'", "\""));
    List max = jsonDecode(jsonExtraction
        .elementAt(areaCode * 3 + 2)
        .group(0)
        .replaceAll("\'", "\""));
    for (int i = 0; i < names.length; i++) {
      result[names[i]] = TrafficInfo(int.parse(cur[i]), int.parse(max[i]));
    }

    return result;
  }
}

class UnsuitableTimeException implements Exception {}

class TrafficInfo {
  int current;
  int max;

  TrafficInfo(this.current, this.max);
}
