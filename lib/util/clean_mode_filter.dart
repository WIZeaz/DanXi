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

class CleanModeFilter {
  static const List<String> DELETE_EMOJI = [
    '😅',
    '😄',
    '😋',
    '🥰',
    '🤭',
    '😀',
    '😍',
    '😃'
  ];
  static const List<String> CN_FILTER_TEXT = [
    '差不多得了',
    '傻逼',
    '伞兵',
    'nmsl',
    'sb',
    '4000+',
    '你妈死了',
    '批'
  ];

  static cleanText(String content) {
    String newContent = content;
    DELETE_EMOJI
        .forEach((element) => newContent = newContent.replaceAll(element, ' '));

    // Before we decide how to deal with filtered texts (in either Markdown or HTML syntax)
    // and whether they should be hard-coded, we won't enable it.

    // CN_FILTER_TEXT.forEach((element) {
    //   final filterRegex = RegExp(
    //       r'[\u4E00-\u9FFF\b]' + RegExp.escape(element) + r'[\u4E00-\u9FFF\b]',
    //       caseSensitive: false,
    //       unicode: true);
    //   newContent = newContent.replaceAll(filterRegex, r' !@#$% ');
    // });
    return newContent;
  }
}