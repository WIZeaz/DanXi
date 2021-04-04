/*
 *     Copyright (C) 2021  w568w
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

import 'package:dan_xi/feature/base_feature.dart';
import 'package:dan_xi/generated/l10n.dart';
import 'package:dan_xi/model/person.dart';
import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';

class WelcomeFeature extends Feature {
  PersonInfo _info;
  String _helloQuote = "";

  @override
  void buildFeature() {
    _info = Provider.of<ValueNotifier<PersonInfo>>(context)?.value;
    int time = DateTime.now().hour;
    if (time >= 23 || time <= 4) {
      _helloQuote = S.of(context).late_night;
    } else if (time >= 5 && time <= 8) {
      _helloQuote = S.of(context).good_morning;
    } else if (time >= 9 && time <= 11) {
      _helloQuote = S.of(context).good_noon;
    } else if (time >= 12 && time <= 16) {
      _helloQuote = S.of(context).good_afternoon;
    } else if (time >= 17 && time <= 22) {
      _helloQuote = S.of(context).good_night;
    }
  }

  @override
  String get mainTitle => S.of(context).welcome(_info?.name);

  @override
  String get subTitle => _helloQuote;

  @override
  String get tertiaryTitle => null;
}