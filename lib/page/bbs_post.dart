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

import 'package:dan_xi/common/constant.dart';
import 'package:dan_xi/generated/l10n.dart';
import 'package:dan_xi/model/post.dart';
import 'package:dan_xi/model/reply.dart';
import 'package:dan_xi/public_extension_methods.dart';
import 'package:dan_xi/repository/bbs/post_repository.dart';
import 'package:dan_xi/util/human_duration.dart';
import 'package:dan_xi/util/platform_universal.dart';
import 'package:dan_xi/widget/bbs_editor.dart';
import 'package:dan_xi/widget/platform_app_bar_ex.dart';
import 'package:dan_xi/widget/top_controller.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:flutter_sfsymbols/flutter_sfsymbols.dart';
import 'package:flutter_widget_from_html_core/flutter_widget_from_html_core.dart';
import 'package:url_launcher/url_launcher.dart';

class BBSPostDetail extends StatefulWidget {
  final Map<String, dynamic> arguments;

  const BBSPostDetail({Key key, this.arguments});

  @override
  _BBSPostDetailState createState() => _BBSPostDetailState();
}

class _BBSPostDetailState extends State<BBSPostDetail> {
  BBSPost _post;
  ScrollController _controller = ScrollController();
  int _currentBBSPage;
  List<Reply> _lastReplies;
  AsyncSnapshot _lastSnapshotData;
  bool _isRefreshing;
  bool _isEndIndicatorShown;
  static const POST_COUNT_PER_PAGE = 10;

  @override
  void initState() {
    super.initState();
    _post = widget.arguments['post'];

    _currentBBSPage = 1;
    _lastReplies = [];
    _lastSnapshotData = null;
    _isRefreshing = true;
    _isEndIndicatorShown = false;

    if (_controller != null) {
      // Over-scroll event
      _controller.addListener(() {
        if (_controller.offset >= _controller.position.maxScrollExtent &&
            !_isRefreshing && !_isEndIndicatorShown) {
          _isRefreshing = true;
          setState(() {
            _currentBBSPage++;
          });
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PlatformScaffold(
      iosContentPadding: true,
      iosContentBottomPadding: true,
      appBar: PlatformAppBarX(
        title: TopController(
          controller: _controller,
          child: Text(S.of(context).forum),
        ),
        trailingActions: [
          PlatformIconButton(
            padding: EdgeInsets.zero,
            icon: PlatformX.isAndroid
                ? const Icon(Icons.reply)
                : const Icon(SFSymbols.arrowshape_turn_up_left),
            onPressed: () {
              BBSEditor.createNewReply(context, _post.id, null);
            },
          )
        ],
      ),
      body: RefreshIndicator(
          color: Theme.of(context).accentColor,
          onRefresh: () async {
            refreshSelf();
          },
          child: MediaQuery.removePadding(
              context: context,
              removeTop: true,
              child: PrimaryScrollController(
                controller: _controller,
                child:
                    FutureBuilder(
                        builder: (_, AsyncSnapshot<List<Reply>> snapshot) {
                          switch (snapshot.connectionState) {
                            case ConnectionState.none:
                            case ConnectionState.waiting:
                            case ConnectionState.active:
                              _isRefreshing = true;
                              /*return ListView.builder(
                                  primary: true,
                                  itemBuilder: (context, index) =>
                                      _buildListItem(null, index),
                                  itemCount: _lastPageItems.length + 1,
                              );*/
                              _isRefreshing = true;
                              if (_lastSnapshotData == null) return Container(
                                padding: EdgeInsets.all(8),
                                child: Center(
                                  child: PlatformCircularProgressIndicator()
                                ),
                              );
                              return _buildPageWhileLoading(_lastSnapshotData.data);
                              break;
                            case ConnectionState.done:
                              _isRefreshing = false;
                              if (snapshot.hasError) {
                                return _buildErrorWidget();
                              } else {
                                _lastSnapshotData = snapshot;
                                var l = snapshot.data;
                                return _buildPage(snapshot.data);
                                /*return  ListView.builder(
                                        primary: true,
                                        itemBuilder: (context, index) =>
                                            _buildListItem(l, index),
                                        itemCount: (_currentBBSPage) * POST_COUNT_PER_PAGE);*/
                              }
                              break;
                          }
                          return null;
                        },
                        future: PostRepository.getInstance().loadReplies(_post, _currentBBSPage)),
              )
          )),
    );
  }

  Widget _buildPage(List<Reply> data) {
    return PlatformWidget(
      // Add a scrollbar on desktop platform
        material: (_, __) => Scrollbar(
          controller: _controller,
          interactive: PlatformX.isDesktop,
          child: ListView.builder(
            physics: const AlwaysScrollableScrollPhysics(),
            controller: _controller,
            itemCount: (_currentBBSPage) * POST_COUNT_PER_PAGE,
            itemBuilder: (context, index) =>
                _buildListItem(index, data, true),
          ),
        ),
        cupertino: (_, __) => CupertinoScrollbar(
          controller: _controller,
          child: ListView.builder(
            physics: const AlwaysScrollableScrollPhysics(),
            controller: _controller,
            itemCount: _currentBBSPage * POST_COUNT_PER_PAGE,
            itemBuilder: (context, index) =>
                _buildListItem(index, data, true),
          ),
        ));
  }

  Widget _buildPageWhileLoading(List<Reply> data) {
    return PlatformWidget(
      // Add a scrollbar on desktop platform
        material: (_, __) => Scrollbar(
          controller: _controller,
          interactive: PlatformX.isDesktop,
          child: ListView.builder(
            physics: const AlwaysScrollableScrollPhysics(),
            controller: _controller,
            itemCount: (_lastSnapshotData == null
                ? _currentBBSPage
                : _currentBBSPage - 1) *
                POST_COUNT_PER_PAGE +
                1,
            itemBuilder: (context, index) =>
                _buildListItem(index, data, false),
          ),
        ),
        cupertino: (_, __) => CupertinoScrollbar(
          controller: _controller,
          child: ListView.builder(
            physics: const AlwaysScrollableScrollPhysics(),
            controller: _controller,
            itemCount: (_lastSnapshotData == null
                ? _currentBBSPage
                : _currentBBSPage - 1) *
                POST_COUNT_PER_PAGE +
                1,
            itemBuilder: (context, index) =>
                _buildListItem(index, data, false),
          ),
        ));
  }

  Widget _buildListItem(int index, List<Reply> e, bool isNewData) {
    if (isNewData && index >= _lastReplies.length) {
      try {
        // TODO: migrate to [_lastReplies.addAll(e)];
        _lastReplies.add(e[index % POST_COUNT_PER_PAGE]);
      } catch (e) {
        if (!_isEndIndicatorShown) {
          _isEndIndicatorShown = true;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: <Widget>[
              Text(S.of(context).end_reached),
              const SizedBox(height: 16,)
            ],
          );
        }
        return null;
      }
    }
    if (index >= _lastReplies.length) return GestureDetector(child: Center(child: PlatformCircularProgressIndicator()),);
    return _wrapListItemInCanvas(_lastReplies[index], index == 0) ;
  }

  Widget _buildErrorWidget() => GestureDetector(
        child: Center(
          child: Text(S.of(context).failed),
        ),
        onTap: () {
          refreshSelf();
        },
      );

  List<Widget> _buildContextMenu(Reply e) {
    List<Widget> list = [];
    list.add(PlatformWidget(
      cupertino: (_, __) => CupertinoActionSheetAction(
        onPressed: () {
          Navigator.of(context).pop();
          BBSEditor.reportPost(context, e.id);
        },
        child: Text(S.of(context).report),
      ),
      material: (_, __) => ListTile(
        title: Text(S.of(context).report),
        onTap: () {
          Navigator.of(context).pop();
          BBSEditor.reportPost(context, e.id);
        },
      ),
    ));
    return list;
  }

  Widget _wrapListItemInCanvas(Reply e, bool generateTags) => Material(
          child: _getListItems(e, generateTags));

  Widget _getListItems(Reply e, bool generateTags) => GestureDetector(
    onLongPress: () {
      showPlatformModalSheet(
          context: context,
          builder: (_) => PlatformWidget(
            cupertino: (_, __) => CupertinoActionSheet(
              actions: _buildContextMenu(e),
              cancelButton: CupertinoActionSheetAction(
                child: Text(S.of(context).cancel),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ),
            material: (_, __) => Container(
              height: 300,
              child: Column(
                children: _buildContextMenu(e),
              ),
            ),
          ));
    },
    child: Card(
      //margin: EdgeInsets.fromLTRB(10,8,10,8),
        child: ListTile(
          dense: true,
          title: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (generateTags)
                Padding(
                  padding: EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    children: _generateTagWidgets(_post),
                  ),
                ),
              Padding(
                padding: EdgeInsets.symmetric(vertical: 6),
                child: Text(
                  "[${e.username}]",
                ),
              ),

              if (e.reply_to != null)
                Padding(
                  padding: EdgeInsets.symmetric(vertical: 4),
                  child:  _getListItems(_lastReplies.firstWhere((element) => element.id == e.reply_to), false),
                ),

              Align(
                alignment: Alignment.topLeft,
                child: HtmlWidget(
                  e.content,
                  textStyle: TextStyle(fontSize: 16),
                  onTapUrl: (url) => launch(url),
                ),
              ),
            ],
          ),
          subtitle: Column(children: [
            const SizedBox(
              height: 8,
            ),
            Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
              Text(
                "#${e.id}",
                style:
                TextStyle(color: Theme.of(context).hintColor, fontSize: 12),
              ),
              Text(
                HumanDuration.format(context, DateTime.parse(e.date_created)),
                style:
                TextStyle(color: Theme.of(context).hintColor, fontSize: 12),
              ),
              GestureDetector(
                child: Text(S.of(context).report, style: TextStyle(color: Theme.of(context).hintColor, fontSize: 12)),
                onTap: () {
                  BBSEditor.reportPost(context, e.id);
                },
              ),
            ]),
          ]),
          onTap: () {
            BBSEditor.createNewReply(context, _post.id, e.id);
          },
        )),
  );

  List<Widget> _generateTagWidgets(BBSPost e) {
    List<Widget> _tags = [
      const SizedBox(
        width: 2,
      ),
    ];
    e.tag.forEach((element) {
      _tags.add(Container(
        padding: EdgeInsets.symmetric(horizontal: 8),
        decoration: BoxDecoration(
          border: Border.all(
            color: Constant.getColorFromString(element.color),
            width: 1,
          ),
          borderRadius: BorderRadius.circular(16),
          //color: Constant.getColorFromString(element.color).withAlpha(25),
        ),
        child: Text(
          element.name,
          style: TextStyle(
              fontSize: 14,
              color: Constant.getColorFromString(element
                  .color) //.computeLuminance() <= 0.5 ? Colors.black : Colors.white,
              ),
        ),
      ));
      _tags.add(const SizedBox(
        width: 6,
      ));
    });
    return _tags;
  }
}
