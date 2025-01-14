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

import 'package:dan_xi/common/constant.dart';
import 'package:dan_xi/model/post_tag.dart';
import 'package:dan_xi/widget/round_chip.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
/// A wrapped container for [PostTag].
class BBSTagsContainer extends StatefulWidget {
  final List<PostTag>? tags;
  final OnTapTag? onTap;

  const BBSTagsContainer({Key? key, required this.tags, this.onTap})
      : super(key: key);

  @override
  _BBSTagsContainerState createState() => _BBSTagsContainerState();
}

class _BBSTagsContainerState extends State<BBSTagsContainer> {
  FocusNode _searchFocus = FocusNode();
  List<PostTag>? filteredTags;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      behavior: HitTestBehavior.translucent,
      onTapDown: (_) {
        if (_searchFocus.hasFocus) _searchFocus.unfocus();
      },
      child: Column(
        children: [
          CupertinoSearchTextField(
            focusNode: _searchFocus,
            onChanged: (filter) {
              setState(() {
                filteredTags = widget.tags!
                    .where((value) =>
                        value.name!.toLowerCase().contains(filter.toLowerCase()))
                    .toList();
              });
            },
          ),
          Wrap(
              children: (filteredTags ?? widget.tags)!
                  .map(
                    (e) => Padding(
                        padding: EdgeInsets.only(top: 16, right: 12),
                        child: RoundChip(
                            label: e.name,
                            color: Constant.getColorFromString(e.color),
                            onTap: () => widget.onTap?.call(e))),
                  )
                  .toList())
        ],
      ),
    );
  }
}

typedef OnTapTag = void Function(PostTag tag);
