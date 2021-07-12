/*
 *     Copyright (C) 2021 kavinzhao
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

import 'dart:io';

import 'package:dan_xi/common/constant.dart';
import 'package:dan_xi/generated/l10n.dart';
import 'package:dan_xi/model/post_tag.dart';
import 'package:dan_xi/repository/bbs/post_repository.dart';
import 'package:dan_xi/util/noticing.dart';
import 'package:dan_xi/widget/material_x.dart';
import 'package:flutter/material.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:flutter_sfsymbols/flutter_sfsymbols.dart';
import 'package:flutter_tagging/flutter_tagging.dart';
import 'package:image_picker/image_picker.dart';
import 'package:flutter_progress_dialog/flutter_progress_dialog.dart';
import 'package:flutter_progress_dialog/src/progress_dialog.dart';

class BBSEditor {
  /// Returns true on success, false on failure
  static Future<bool> createNewPost(BuildContext context) async {
    final PostEditorText content =
        await _showEditor(context, S.of(context).new_post, allowTags: true);
    if (content?.content == null) return false;
    final int responseCode = await PostRepository.getInstance()
        .newPost(content.content, tags: content.tags)
        .onError((error, stackTrace) => -1);
    if (responseCode != 200) {
      Noticing.showNotice(context, S.of(context).post_failed,
          title: S.of(context).fatal_error, androidUseSnackbar: false);
      return false;
    }
    return true;
  }

  static Future<void> createNewReply(
      BuildContext context, int discussionId, int postId) async {
    final String content = (await _showEditor(
            context,
            postId == null
                ? S.of(context).reply_to(discussionId)
                : S.of(context).reply_to(postId)))
        .content;
    if (content == null || content.trim() == "") return;
    final int responseCode = await PostRepository.getInstance()
        .newReply(discussionId, postId, content)
        .onError((error, stackTrace) => Noticing.showNotice(
            context, S.of(context).reply_failed(error),
            title: S.of(context).fatal_error, androidUseSnackbar: false));
    // Note: postId refers to the specific post the user is replying to, can be NULL
    if (responseCode != 200) {
      Noticing.showNotice(context, S.of(context).reply_failed(responseCode));
    }
  }

  static Future<void> reportPost(BuildContext context, int postId) async {
    final String content =
        (await _showEditor(context, S.of(context).reason_report_post(postId)))
            .content;
    if (content == null || content.trim() == "") return;

    int responseCode =
        await PostRepository.getInstance().reportPost(postId, content);
    if (responseCode != 200) {
      Noticing.showNotice(context, S.of(context).report_failed(responseCode),
          title: S.of(context).fatal_error, androidUseSnackbar: false);
    } else {
      Noticing.showNotice(context, S.of(context).report_success);
    }
  }

  static Future<PostEditorText> _showEditor(BuildContext context, String title,
      {bool allowTags = false}) async {
    final textController = TextEditingController();
    List<PostTag> _tags = [];
    List<PostTag> _allTags;
    return await showPlatformDialog<PostEditorText>(
        context: context,
        builder: (BuildContext context) => PlatformAlertDialog(
              title: Text(title),
              content: Column(children: [
                if (allowTags)
                  Padding(
                    padding: EdgeInsets.only(bottom: 12),
                    child: ThemedMaterial(
                      child: FlutterTagging<PostTag>(
                          initialItems: _tags,
                          textFieldConfiguration: TextFieldConfiguration(
                            decoration: InputDecoration(
                              labelStyle: TextStyle(fontSize: 12),
                              labelText: S.of(context).select_tags,
                            ),
                          ),
                          findSuggestions: (String filter) async {
                            if (_allTags == null)
                              _allTags =
                                  await PostRepository.getInstance().loadTags();
                            return _allTags
                                .where((value) => value.name
                                    .toLowerCase()
                                    .contains(filter.toLowerCase()))
                                .toList();
                          },
                          additionCallback: (value) =>
                              PostTag(value, Constant.randomColor, 0),
                          onAdded: (tag) => tag,
                          configureSuggestion: (tag) => SuggestionConfiguration(
                                title: Text(
                                  tag.name,
                                  style: TextStyle(
                                      color: Constant.getColorFromString(
                                          tag.color)),
                                ),
                                subtitle: Row(
                                  children: [
                                    Icon(
                                      SFSymbols.flame,
                                      color: Constant.getColorFromString(
                                          tag.color),
                                      size: 12,
                                    ),
                                    const SizedBox(
                                      width: 2,
                                    ),
                                    Text(
                                      tag.count.toString(),
                                      style: TextStyle(
                                          fontSize: 13,
                                          color: Constant.getColorFromString(
                                              tag.color)),
                                    ),
                                  ],
                                ),
                                additionWidget: Chip(
                                  avatar: Icon(
                                    Icons.add_circle,
                                    color: Colors.white,
                                  ),
                                  label: Text(S.of(context).add_new_tag),
                                  labelStyle: TextStyle(
                                    color: Colors.white,
                                    fontSize: 14.0,
                                    fontWeight: FontWeight.w300,
                                  ),
                                  backgroundColor:
                                      Theme.of(context).accentColor,
                                ),
                              ),
                          configureChip: (lang) => ChipConfiguration(
                                label: Text(lang.name),
                                backgroundColor:
                                    Constant.getColorFromString(lang.color),
                                labelStyle: TextStyle(
                                    color:
                                        Constant.getColorFromString(lang.color)
                                                    .computeLuminance() >=
                                                0.5
                                            ? Colors.black
                                            : Colors.white),
                                deleteIconColor:
                                    Constant.getColorFromString(lang.color)
                                                .computeLuminance() >=
                                            0.5
                                        ? Colors.black
                                        : Colors.white,
                              ),
                          onChanged: () {}),
                    ),
                  ),
                PlatformTextField(
                  controller: textController,
                  keyboardType: TextInputType.multiline,
                  maxLines: null,
                  minLines: 5,
                  autofocus: true,
                ),
              ]),
              actions: [
                PlatformDialogAction(
                    child: Text(S.of(context).cancel),
                    onPressed: () {
                      Navigator.of(context).pop<PostEditorText>(null);
                    }),
                PlatformDialogAction(
                    child: Text(S.of(context).add_image),
                    onPressed: () {
                      _uploadImage(context, textController);
                    }),
                PlatformDialogAction(
                    child: Text(S.of(context).submit),
                    onPressed: () async {
                      Navigator.of(context).pop<PostEditorText>(
                          PostEditorText(textController.text, _tags));
                    }),
              ],
            ));
  }

  static Future<void> _uploadImage(
      BuildContext context, TextEditingController _controller) async {
    final ImagePicker _picker = ImagePicker();
    final PickedFile _file =
        await _picker.getImage(source: ImageSource.gallery);
    if (_file == null) return;
    ProgressFuture progressDialog = showProgressDialog(
        loadingText: S.of(context).uploading_image, context: context);
    try {
      await PostRepository.getInstance().uploadImage(File(_file.path)).then(
          (value) {
        if (value != null) _controller.text += "![]($value)";
        //"showAnim: true" makes it crash. Don't know the reason.
        progressDialog.dismiss(showAnim: false);
        return value;
      }, onError: (e) {
        progressDialog.dismiss(showAnim: false);
        Noticing.showNotice(context, S.of(context).uploading_image_failed);
        throw e;
      });
    } catch (ignored) {}
  }
}

class PostEditorText {
  final String content;
  final List<PostTag> tags;

  PostEditorText(this.content, this.tags);
}
