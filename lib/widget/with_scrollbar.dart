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

import 'package:dan_xi/util/platform_universal.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';

//import 'custom_cupertino_scrollbar.dart';

/// A widget that will add a scroll bar for its child.
class WithScrollbar extends StatefulWidget {
  final ScrollController? controller;
  final Widget? child;

  const WithScrollbar({Key? key, this.controller, this.child}) : super(key: key);

  @override
  _WithScrollbarState createState() => _WithScrollbarState();
}

class _WithScrollbarState extends State<WithScrollbar> {
  @override
  Widget build(BuildContext context) {
    return PlatformWidget(
        // Add a scrollbar on desktop platform
        material: (_, __) => Scrollbar(
          controller: widget.controller,
              interactive: PlatformX.isDesktop,
              child: widget.child!,
            ),
        cupertino: (_, __) => CupertinoScrollbar(
              controller: widget.controller,
              child: widget.child!,
            ));
  }
}