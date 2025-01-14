/*
 *     Copyright (C) 2021 DanXi-Dev
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

import 'dart:ui';

import 'package:dan_xi/common/constant.dart';
import 'package:dan_xi/common/pubspec.yaml.g.dart' as Pubspec;
import 'package:dan_xi/generated/l10n.dart';
import 'package:dan_xi/master_detail/master_detail_view.dart';
import 'package:dan_xi/model/person.dart';
import 'package:dan_xi/page/open_source_license.dart';
import 'package:dan_xi/page/platform_subpage.dart';
import 'package:dan_xi/page/subpage_bbs.dart';
import 'package:dan_xi/page/subpage_main.dart';
import 'package:dan_xi/page/subpage_timetable.dart';
import 'package:dan_xi/provider/ad_manager.dart';
import 'package:dan_xi/provider/settings_provider.dart';
import 'package:dan_xi/provider/state_provider.dart';
import 'package:dan_xi/public_extension_methods.dart';
import 'package:dan_xi/util/browser_util.dart';
import 'package:dan_xi/util/clean_mode_filter.dart';
import 'package:dan_xi/util/flutter_app.dart';
import 'package:dan_xi/util/noticing.dart';
import 'package:dan_xi/util/platform_universal.dart';
import 'package:dan_xi/util/scroller_fix/primary_scroll_page.dart';
import 'package:dan_xi/util/viewport_utils.dart';
import 'package:dan_xi/util/win32/auto_start.dart';
import 'package:dan_xi/widget/login_dialog/login_dialog.dart';
import 'package:dan_xi/widget/post_render.dart';
import 'package:dan_xi/widget/render/render_impl.dart';
import 'package:dan_xi/widget/with_scrollbar.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_cache_manager/flutter_cache_manager.dart';
import 'package:flutter_email_sender/flutter_email_sender.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:google_mobile_ads/google_mobile_ads.dart';
import 'package:in_app_review/in_app_review.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

class SettingsSubpage extends PlatformSubpage
    with PageWithPrimaryScrollController {
  @override
  _SettingsSubpageState createState() => _SettingsSubpageState();

  SettingsSubpage({Key? key});

  @override
  String get debugTag => "SettingsPage";

  @override
  Create<String> get title => (cxt) => S.of(cxt).settings;
}

class _SettingsSubpageState extends State<SettingsSubpage>
    with AutomaticKeepAliveClientMixin {
  /// All open-source license for the app.
  static const List<LicenseItem> _LICENSE_ITEMS = [
    LicenseItem("asn1lib", LICENSE_BSD, "https://github.com/wstrange/asn1lib"),
    LicenseItem("cached_network_image", LICENSE_MIT,
        "https://github.com/Baseflow/flutter_cached_network_image"),
    LicenseItem(
        "system_tray", LICENSE_MIT, "https://github.com/antler119/system_tray"),
    LicenseItem(
        "win32", LICENSE_BSD_3_0_CLAUSE, "https://github.com/timsneath/win32"),
    LicenseItem("collection", LICENSE_BSD_3_0_CLAUSE,
        "https://github.com/dart-lang/collection"),
    LicenseItem(
        "meta", LICENSE_BSD_3_0_CLAUSE, "https://github.com/dart-lang/sdk"),
    LicenseItem("bitsdojo_window", LICENSE_MIT,
        "https://github.com/bitsdojo/bitsdojo_window"),
    LicenseItem("flutter_layout_grid", LICENSE_MIT,
        "https://github.com/madewithfelt/flutter_layout_grid"),
    LicenseItem(
        "flutter_js", LICENSE_MIT, "https://github.com/abner/flutter_js"),
    LicenseItem("fluttertoast", LICENSE_MIT,
        "https://github.com/PonnamKarthik/FlutterToast"),
    LicenseItem("markdown", LICENSE_BSD_3_0_CLAUSE,
        "https://github.com/dart-lang/markdown"),
    LicenseItem("flutter_typeahead", LICENSE_BSD_2_0_CLAUSE,
        "https://github.com/AbdulRahmanAlHamali/flutter_typeahead"),
    LicenseItem("flutter_markdown", LICENSE_BSD_3_0_CLAUSE,
        "https://github.com/flutter/packages/tree/master/packages/flutter_markdown"),
    LicenseItem("image_picker", LICENSE_APACHE_2_0,
        "https://github.com/flutter/plugins/tree/master/packages/image_picker/image_picker"),
    LicenseItem("Kotlin Stdlib Jdk7", LICENSE_APACHE_2_0,
        "https://github.com/JetBrains/kotlin"),
    LicenseItem("google_mobile_ads", LICENSE_APACHE_2_0,
        "https://github.com/googleads/googleads-mobile-flutter"),
    LicenseItem("auto_size_text", LICENSE_MIT,
        "https://github.com/leisim/auto_size_text"),
    LicenseItem("beautiful_soup_dart", LICENSE_MIT,
        "https://github.com/mzdm/beautiful_soup"),
    LicenseItem("build_runner", LICENSE_BSD,
        "https://github.com/dart-lang/build/tree/master/build_runner"),
    LicenseItem(
        "catcher", LICENSE_APACHE_2_0, "https://github.com/jhomlala/catcher"),
    LicenseItem("clipboard", LICENSE_BSD,
        "https://github.com/samuelezedi/flutter_clipboard"),
    LicenseItem("cupertino_icons", LICENSE_MIT,
        "https://github.com/flutter/cupertino_icons"),
    LicenseItem("desktop_window", LICENSE_MIT,
        "https://github.com/mix1009/desktop_window"),
    LicenseItem("dio", LICENSE_MIT, "https://github.com/flutterchina/dio"),
    LicenseItem("dio_cookie_manager", LICENSE_MIT,
        "https://github.com/flutterchina/dio"),
    LicenseItem("dio_log", LICENSE_APACHE_2_0,
        "https://github.com/flutterplugin/dio_log"),
    LicenseItem("event_bus", LICENSE_MIT,
        "https://github.com/marcojakob/dart-event-bus"),
    LicenseItem("file_picker", LICENSE_MIT,
        "https://github.com/miguelpruivo/plugins_flutter_file_picker"),
    LicenseItem("flutter", LICENSE_BSD_3_0_CLAUSE,
        "https://github.com/flutter/flutter"),
    LicenseItem("flutter_email_sender", LICENSE_APACHE_2_0,
        "https://github.com/sidlatau/flutter_email_sender"),
    LicenseItem("flutter_html", LICENSE_MIT,
        "https://github.com/Sub6Resources/flutter_html"),
    LicenseItem("flutter_inappwebview", LICENSE_APACHE_2_0,
        "https://github.com/pichillilorenzo/flutter_inappwebview"),
    LicenseItem("flutter_linkify", LICENSE_MIT,
        "https://github.com/Cretezy/flutter_linkify"),
    LicenseItem("flutter_localizations", LICENSE_BSD_3_0_CLAUSE,
        "https://api.flutter.dev/flutter/flutter_localizations/flutter_localizations-library.html"),
    LicenseItem("flutter_phoenix", LICENSE_MIT,
        "https://github.com/mobiten/flutter_phoenix"),
    LicenseItem("flutter_platform_widgets", LICENSE_MIT,
        "https://github.com/stryder-dev/flutter_platform_widgets"),
    LicenseItem("flutter_progress_dialog", LICENSE_APACHE_2_0,
        "https://github.com/wuzhendev/flutter_progress_dialog"),
    LicenseItem("flutter_sfsymbols", LICENSE_APACHE_2_0,
        "https://github.com/virskor/flutter_sfsymbols"),
    LicenseItem("flutter_tagging", LICENSE_BSD,
        "https://github.com/sarbagyastha/flutter_tagging"),
    LicenseItem("flutter_test", LICENSE_BSD_3_0_CLAUSE,
        "https://api.flutter.dev/flutter/flutter_test/flutter_test-library.html"),
    LicenseItem("gallery_saver", LICENSE_APACHE_2_0,
        "https://github.com/CarnegieTechnologies/gallery_saver"),
    LicenseItem("http", LICENSE_BSD, "https://github.com/dart-lang/http"),
    LicenseItem(
        "ical", LICENSE_BSD_3_0_CLAUSE, "https://github.com/dartclub/ical"),
    LicenseItem("in_app_review", LICENSE_MIT,
        "https://github.com/britannio/in_app_review"),
    LicenseItem("intl", LICENSE_BSD, "https://github.com/dart-lang/intl"),
    LicenseItem("json_serializable", LICENSE_BSD,
        "https://github.com/google/json_serializable.dart/tree/master/json_serializable"),
    LicenseItem("linkify", LICENSE_MIT, "https://github.com/Cretezy/linkify"),
    LicenseItem("pubspec_generator", LICENSE_MIT,
        "https://github.com/PlugFox/pubspec_generator"),
    LicenseItem(
        "open_file", LICENSE_BSD, "https://github.com/crazecoder/open_file"),
    LicenseItem(
        "package_info", LICENSE_BSD, "https://github.com/flutter/plugins"),
    LicenseItem(
        "path_provider", LICENSE_BSD, "https://github.com/flutter/plugins"),
    LicenseItem("permission_handler", LICENSE_MIT,
        "https://github.com/baseflowit/flutter-permission-handler"),
    LicenseItem("photo_view", LICENSE_MIT,
        "https://github.com/renancaraujo/photo_view"),
    LicenseItem(
        "provider", LICENSE_MIT, "https://github.com/rrousselGit/provider"),
    LicenseItem(
        "qr_flutter", LICENSE_BSD, "https://github.com/theyakka/qr.flutter"),
    LicenseItem(
        "quick_actions", LICENSE_BSD, "https://github.com/flutter/plugins"),
    LicenseItem("screen", LICENSE_MIT,
        "https://github.com/clovisnicolas/flutter_screen"),
    LicenseItem("share", LICENSE_BSD, "https://github.com/flutter/plugins"),
    LicenseItem("shared_preferences", LICENSE_BSD,
        "https://github.com/flutter/plugins"),
    LicenseItem(
        "url_launcher", LICENSE_BSD, "https://github.com/flutter/plugins"),
    LicenseItem("screen_brightness", LICENSE_MIT,
        "https://github.com/aaassseee/screen_brightness"),
  ];
  BannerAd? myBanner;

  @override
  void initState() {
    super.initState();
    myBanner = AdManager.loadBannerAd(3); // 3 for settings page
  }

  String? _clearCacheSubtitle;

  Future<void> _deleteAllDataAndExit() async {
    SharedPreferences _preferences = await SharedPreferences.getInstance();
    _preferences.clear().then((value) => FlutterApp.restartApp(context));
  }

  void initLogin({bool forceLogin = false}) {
    _showLoginDialog(forceLogin: forceLogin);
  }

  /// Pop up a dialog where user can give his name & password.
  void _showLoginDialog({bool forceLogin = false}) {
    ValueNotifier<PersonInfo?> _infoNotifier = StateProvider.personInfo;
    showPlatformDialog(
        context: context,
        barrierDismissible: false,
        builder: (BuildContext context) => LoginDialog(
            sharedPreferences: SettingsProvider.getInstance().preferences,
            personInfo: _infoNotifier,
            dismissible: forceLogin));
  }

  List<Widget> _buildCampusAreaList(BuildContext context) {
    List<Widget> list = [];
    Function onTapListener = (Campus campus) {
      SettingsProvider.getInstance().campus = campus;
      Navigator.of(context).pop();
      RefreshHomepageEvent().fire();
      refreshSelf();
    };
    Constant.CAMPUS_VALUES.forEach((value) {
      list.add(PlatformWidget(
        cupertino: (_, __) => CupertinoActionSheetAction(
          onPressed: () => onTapListener(value),
          child: Text(value.displayTitle(context)!),
        ),
        material: (_, __) => ListTile(
          title: Text(value.displayTitle(context)!),
          onTap: () => onTapListener(value),
        ),
      ));
    });
    return list;
  }

  List<Widget> _buildFoldBehaviorList(BuildContext context) {
    List<Widget> list = [];
    Function onTapListener = (FoldBehavior value) {
      SettingsProvider.getInstance().fduholeFoldBehavior = value;
      RefreshBBSEvent().fire();
      Navigator.of(context).pop();
      refreshSelf();
    };
    FoldBehavior.values.forEach((value) {
      list.add(PlatformWidget(
        cupertino: (_, __) => CupertinoActionSheetAction(
          onPressed: () => onTapListener(value),
          child: Text(value.displayTitle(context)!),
        ),
        material: (_, __) => ListTile(
          title: Text(value.displayTitle(context)!),
          onTap: () => onTapListener(value),
        ),
      ));
    });
    return list;
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);

    // Load preference fields

    return SafeArea(
        child: WithScrollbar(
            controller: widget.primaryScrollController(context),
            child: RefreshIndicator(
                color: Theme.of(context).accentColor,
                backgroundColor: Theme.of(context).dialogBackgroundColor,
                onRefresh: () async {
                  HapticFeedback.mediumImpact();
                  refreshSelf();
                },
                child: Material(
                  child: ListView(
                      padding: EdgeInsets.all(4),
                      controller: widget.primaryScrollController(context),
                      physics: AlwaysScrollableScrollPhysics(),
                      children: <Widget>[
                        AutoBannerAdWidget(
                          bannerAd: myBanner,
                        ),
                        //Account Selection
                        Card(
                          child: Column(children: <Widget>[
                            ListTile(
                              title: Text(S.of(context).account),
                              leading: PlatformX.isMaterial(context)
                                  ? const Icon(Icons.account_circle)
                                  : const Icon(CupertinoIcons.person_circle),
                              subtitle: Text(
                                  "${StateProvider.personInfo.value!.name} (${StateProvider.personInfo.value!.id})"),
                              onTap: () {
                                showPlatformDialog(
                                  context: context,
                                  barrierDismissible: false,
                                  builder: (BuildContext context) =>
                                      PlatformAlertDialog(
                                    title: Text(S
                                        .of(context)
                                        .logout_question_prompt_title),
                                    content: Text(
                                        S.of(context).logout_question_prompt),
                                    actions: [
                                      PlatformDialogAction(
                                        child: Text(S.of(context).cancel),
                                        onPressed: () =>
                                            Navigator.of(context).pop(),
                                      ),
                                      PlatformDialogAction(
                                          child: Text(
                                            S.of(context).i_see,
                                            style: TextStyle(
                                                color: Theme.of(context)
                                                    .errorColor),
                                          ),
                                          onPressed: () {
                                            Navigator.of(context).pop();
                                            _deleteAllDataAndExit();
                                          })
                                    ],
                                  ),
                                );
                              },
                            ),

                            // Campus
                            ListTile(
                              title: Text(S.of(context).default_campus),
                              leading: PlatformX.isMaterial(context)
                                  ? const Icon(Icons.location_on)
                                  : const Icon(CupertinoIcons.location_fill),
                              subtitle: Text(SettingsProvider.getInstance()
                                  .campus
                                  .displayTitle(context)!),
                              onTap: () {
                                showPlatformModalSheet(
                                    context: context,
                                    builder: (BuildContext context) =>
                                        PlatformWidget(
                                          cupertino: (_, __) =>
                                              CupertinoActionSheet(
                                            title: Text(
                                                S.of(context).select_campus),
                                            actions:
                                                _buildCampusAreaList(context),
                                            cancelButton:
                                                CupertinoActionSheetAction(
                                              child: Text(S.of(context).cancel),
                                              onPressed: () {
                                                Navigator.of(context).pop();
                                              },
                                            ),
                                          ),
                                          material: (_, __) => Container(
                                            height: 300,
                                            child: Column(
                                              children:
                                                  _buildCampusAreaList(context),
                                            ),
                                          ),
                                        ));
                              },
                            ),
                          ]),
                        ),

                        // Accessibility
                        Card(
                          child: ListTile(
                            title: Text(S.of(context).accessibility_coloring),
                            leading: Icon(Icons.accessibility_new_rounded),
                            subtitle: Text(SettingsProvider.getInstance()
                                    .useAccessibilityColoring
                                ? S.of(context).enabled
                                : S.of(context).disabled),
                            onTap: () {
                              SettingsProvider.getInstance()
                                      .useAccessibilityColoring =
                                  !SettingsProvider.getInstance()
                                      .useAccessibilityColoring;
                              RefreshBBSEvent(refreshAll: true).fire();
                              setState(() {});
                            },
                          ),
                        ),

                        // FDUHOLE
                        Card(
                          child: Column(
                            children: [
                              if (PlatformX.isWindows)
                                SwitchListTile(
                                  title: Text(
                                      S.of(context).windows_auto_start_title),
                                  secondary: const Icon(Icons.settings_power),
                                  subtitle: Text(S
                                      .of(context)
                                      .windows_auto_start_description),
                                  value: WindowsAutoStart.autoStart,
                                  onChanged: (bool value) async {
                                    WindowsAutoStart.autoStart = value;
                                    await Noticing.showNotice(
                                        context,
                                        S
                                            .of(context)
                                            .windows_auto_start_wait_dialog_message,
                                        title: S
                                            .of(context)
                                            .windows_auto_start_wait_dialog_title,
                                        useSnackBar: false);
                                    refreshSelf();
                                  },
                                ),
                              ListTile(
                                title:
                                    Text(S.of(context).fduhole_nsfw_behavior),
                                leading: PlatformX.isMaterial(context)
                                    ? const Icon(Icons.hide_image)
                                    : const Icon(CupertinoIcons.eye_slash),
                                subtitle: Text(SettingsProvider.getInstance()
                                    .fduholeFoldBehavior
                                    .displayTitle(context)!),
                                onTap: () {
                                  showPlatformModalSheet(
                                      context: context,
                                      builder: (BuildContext context) =>
                                          PlatformWidget(
                                            cupertino: (_, __) =>
                                                CupertinoActionSheet(
                                              title: Text(S
                                                  .of(context)
                                                  .fduhole_nsfw_behavior),
                                              actions: _buildFoldBehaviorList(
                                                  context),
                                              cancelButton:
                                                  CupertinoActionSheetAction(
                                                child:
                                                    Text(S.of(context).cancel),
                                                onPressed: () {
                                                  Navigator.of(context).pop();
                                                },
                                              ),
                                            ),
                                            material: (_, __) => Column(
                                              mainAxisSize: MainAxisSize.min,
                                              children: _buildFoldBehaviorList(
                                                  context),
                                            ),
                                          ));
                                },
                              ),
                              SwitchListTile(
                                title: Text(S.of(context).fduhole_clean_mode),
                                secondary: const Icon(Icons.ac_unit),
                                subtitle: Text(S
                                    .of(context)
                                    .fduhole_clean_mode_description),
                                value: SettingsProvider.getInstance().cleanMode,
                                onChanged: (bool value) {
                                  if (value) {
                                    _showCleanModeGuideDialog();
                                  }
                                  setState(() => SettingsProvider.getInstance()
                                      .cleanMode = value);
                                },
                              ),
                              ListTile(
                                leading: Icon(PlatformIcons(context).tag),
                                title: Text(S.of(context).fduhole_hidden_tags),
                                subtitle: Text(S
                                    .of(context)
                                    .fduhole_hidden_tags_description),
                                onTap: () async {
                                  await smartNavigatorPush(
                                      context, '/bbs/tags/blocklist');
                                  RefreshBBSEvent().fire();
                                },
                              ),
                              // Clear Cache
                              ListTile(
                                leading:
                                    Icon(PlatformIcons(context).photoLibrary),
                                title: Text(S.of(context).clear_cache),
                                subtitle: Text(_clearCacheSubtitle ??
                                    S.of(context).clear_cache_description),
                                onTap: () async {
                                  await DefaultCacheManager().emptyCache();
                                  setState(() {
                                    _clearCacheSubtitle =
                                        S.of(context).cache_cleared;
                                  });
                                },
                              ),
                            ],
                          ),
                        ),

                        if (SettingsProvider.getInstance().debugMode)
                          //Theme Selection
                          Card(
                            child: ListTile(
                              title: Text(S.of(context).theme),
                              leading: PlatformX.isMaterial(context)
                                  ? const Icon(Icons.color_lens)
                                  : const Icon(CupertinoIcons.color_filter),
                              subtitle: Text(PlatformX.isMaterial(context)
                                  ? S.of(context).material
                                  : S.of(context).cupertino),
                              onTap: () {
                                PlatformX.isMaterial(context)
                                    ? PlatformProvider.of(context)!
                                        .changeToCupertinoPlatform()
                                    : PlatformProvider.of(context)!
                                        .changeToMaterialPlatform();
                              },
                            ),
                          ),

                        // Sponsor Option
                        if (PlatformX.isMobile)
                          Card(
                            child: ListTile(
                              isThreeLine:
                                  !SettingsProvider.getInstance().isAdEnabled,
                              leading: Icon(
                                PlatformIcons(context).heartSolid,
                              ),
                              title: Text(S.of(context).sponsor_us),
                              subtitle: Text(
                                  SettingsProvider.getInstance().isAdEnabled
                                      ? S.of(context).sponsor_us_enabled
                                      : S.of(context).sponsor_us_disabled),
                              onTap: () async {
                                if (SettingsProvider.getInstance()
                                    .isAdEnabled) {
                                  _toggleAdDisplay();
                                } else {
                                  _toggleAdDisplay();
                                  await _showAdsThankDialog();
                                }
                              },
                            ),
                          ),

                        // About
                        _buildAboutCard()
                      ]),
                ))));
  }

  void _toggleAdDisplay() {
    SettingsProvider.getInstance().isAdEnabled =
        !SettingsProvider.getInstance().isAdEnabled;
    RefreshHomepageEvent().fire();
    RefreshBBSEvent().fire();
    RefreshTimetableEvent().fire();
    setState(() {});
  }

  static const String CLEAN_MODE_EXAMPLE = '`差不多得了😅，自己不会去看看吗😇`';

  Future<bool?> _showAdsDialog() => showPlatformDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
            title: Text(S.of(context).sponsor_us),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(S.of(context).sponsor_us_detail),
              ],
            ),
            actions: [
              TextButton(
                child: Text(S.of(context).cancel),
                onPressed: () => Navigator.of(context).pop(false),
              ),
              TextButton(
                child: Text(S.of(context).i_see),
                onPressed: () => Navigator.of(context).pop(true),
              ),
            ],
          ));

  _showAdsThankDialog() => showPlatformDialog(
      context: context,
      barrierDismissible: true,
      builder: (_) => AlertDialog(
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(S.of(context).thankyouforenablingads),
              ],
            ),
          ));

  _showCleanModeGuideDialog() => showPlatformDialog(
      context: context,
      builder: (_) => AlertDialog(
            title: Text(S.of(context).fduhole_clean_mode),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(S.of(context).fduhole_clean_mode_detail),
                SizedBox(
                  height: 8,
                ),
                Text(S.of(context).before_enabled),
                SizedBox(
                  height: 4,
                ),
                PostRenderWidget(
                  render: kMarkdownRender,
                  content: CLEAN_MODE_EXAMPLE,
                ),
                SizedBox(
                  height: 8,
                ),
                Text(S.of(context).after_enabled),
                SizedBox(
                  height: 4,
                ),
                PostRenderWidget(
                  render: kMarkdownRender,
                  content: CleanModeFilter.cleanText(CLEAN_MODE_EXAMPLE),
                ),
              ],
            ),
            actions: [
              TextButton(
                child: Text(S.of(context).i_see),
                onPressed: () => Navigator.of(context).pop(),
              )
            ],
          ));

  Card _buildAboutCard() {
    final inAppReview = InAppReview.instance;
    final Color _originalDividerColor = Theme.of(context).dividerColor;
    final double _avatarSize =
        (ViewportUtils.getMainNavigatorWidth(context) - 120) / 8;
    final TextStyle? defaultText = Theme.of(context).textTheme.bodyText2;
    final TextStyle linkText = Theme.of(context)
        .textTheme
        .bodyText2!
        .copyWith(color: Theme.of(context).accentColor);

    final developersIcons = Constant.getDevelopers(context)
        .map((e) => ListTile(
              minLeadingWidth: 0,
              contentPadding: EdgeInsets.zero,
              leading: Container(
                  width: _avatarSize,
                  height: _avatarSize,
                  decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      image: DecorationImage(
                          fit: BoxFit.fill, image: AssetImage(e.imageUrl)))),
              title: Text(e.name),
              //subtitle: Text(e.description),
              onTap: () => BrowserUtil.openUrl(e.url, context),
            ))
        .toList();
    return Card(
        child: Theme(
            data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
            child: ExpansionTile(
                maintainState: true,
                leading: PlatformX.isMaterial(context)
                    ? const Icon(Icons.info)
                    : const Icon(CupertinoIcons.info_circle),
                title: Text(S.of(context).about),
                children: <Widget>[
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Container(
                        padding: EdgeInsets.fromLTRB(25, 5, 25, 0),
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: <Widget>[
                              //Description
                              Text(
                                S.of(context).app_description_title,
                                textScaleFactor: 1.1,
                              ),
                              Divider(
                                color: _originalDividerColor,
                              ),
                              Text(S.of(context).app_description),
                              const SizedBox(
                                height: 16,
                              ),
                              //Terms and Conditions
                              Text(
                                S.of(context).terms_and_conditions_title,
                                textScaleFactor: 1.1,
                              ),
                              Divider(
                                color: _originalDividerColor,
                              ),
                              RichText(
                                  text: TextSpan(children: [
                                TextSpan(
                                  style: defaultText,
                                  text: S
                                      .of(context)
                                      .terms_and_conditions_content,
                                ),
                                TextSpan(
                                    style: linkText,
                                    text: S.of(context).privacy_policy,
                                    recognizer: TapGestureRecognizer()
                                      ..onTap = () => BrowserUtil.openUrl(
                                          S.of(context).privacy_policy_url,
                                          context)),
                                TextSpan(
                                  style: defaultText,
                                  text: S
                                      .of(context)
                                      .terms_and_conditions_content_end,
                                ),
                                TextSpan(
                                  style: defaultText,
                                  text: S.of(context).view_ossl,
                                ),
                                TextSpan(
                                    style: linkText,
                                    text: S
                                        .of(context)
                                        .open_source_software_licenses,
                                    recognizer: TapGestureRecognizer()
                                      ..onTap = () => smartNavigatorPush(
                                              context, "/about/openLicense",
                                              arguments: {
                                                "items": _LICENSE_ITEMS
                                              })),
                              ])),
                              const SizedBox(
                                height: 16,
                              ),
                              //Acknowledgement
                              Text(
                                S.of(context).acknowledgements,
                                textScaleFactor: 1.1,
                              ),
                              Divider(
                                color: _originalDividerColor,
                              ),
                              RichText(
                                  text: TextSpan(children: [
                                TextSpan(
                                  style: defaultText,
                                  text: S.of(context).acknowledgements_1,
                                ),
                                TextSpan(
                                    style: linkText,
                                    text: S.of(context).acknowledgement_name_1,
                                    recognizer: TapGestureRecognizer()
                                      ..onTap = () => BrowserUtil.openUrl(
                                          S.of(context).acknowledgement_link_1,
                                          context)),
                                TextSpan(
                                  style: defaultText,
                                  text: S.of(context).acknowledgements_2,
                                ),
                              ])),

                              const SizedBox(
                                height: 16,
                              ),

                              // Authors
                              Text(
                                S.of(context).authors,
                                textScaleFactor: 1.1,
                              ),
                              Divider(
                                color: _originalDividerColor,
                              ),
                              const SizedBox(
                                height: 4,
                              ),
                              Row(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Expanded(
                                      child: Column(
                                          mainAxisAlignment:
                                              MainAxisAlignment.start,
                                          mainAxisSize: MainAxisSize.min,
                                          children: developersIcons.sublist(
                                              0,
                                              (developersIcons.length + 1) ~/
                                                  2)),
                                    ),
                                    Expanded(
                                        child: Column(
                                      mainAxisSize: MainAxisSize.min,
                                      children: developersIcons.sublist(
                                          (developersIcons.length + 1) ~/ 2),
                                    )),
                                  ]),
                              const SizedBox(height: 16),
                              //Version
                              Align(
                                alignment: Alignment.centerRight,
                                child: Text(
                                  '${S.of(context).version} ${Pubspec.major}.${Pubspec.minor}.${Pubspec.patch} build ${Pubspec.build.first}',
                                  textScaleFactor: 0.7,
                                  style: TextStyle(fontWeight: FontWeight.bold),
                                ),
                              ),
                              const SizedBox(height: 4),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.end,
                                children: <Widget>[
                                  Text(
                                    S.of(context).author_descriptor,
                                    textScaleFactor: 0.7,
                                    textAlign: TextAlign.right,
                                  )
                                ],
                              ),
                            ]),
                      ),
                      const SizedBox(height: 8),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: <Widget>[
                          FutureBuilder<bool>(
                            builder: (BuildContext context,
                                AsyncSnapshot<bool> snapshot) {
                              if (snapshot.hasError || snapshot.data == false)
                                return Container();
                              return TextButton(
                                child: Text(S.of(context).rate),
                                onPressed: () {
                                  inAppReview.openStoreListing(
                                    appStoreId: Constant.APPSTORE_APPID,
                                  );
                                },
                              );
                            },
                            future: inAppReview.isAvailable(),
                          ),
                          const SizedBox(width: 8),
                          TextButton(
                            child: Text(S.of(context).contact_us),
                            onPressed: () async {
                              final Email email = Email(
                                body: '',
                                subject: S.of(context).app_feedback,
                                recipients: [S.of(context).feedback_email],
                                isHTML: false,
                              );
                              await FlutterEmailSender.send(email);
                            },
                          ),
                          const SizedBox(width: 8),
                          TextButton(
                            child: Text(S.of(context).project_page),
                            onPressed: () {
                              BrowserUtil.openUrl(
                                  S.of(context).project_url, context);
                            },
                          ),
                          const SizedBox(width: 8),
                        ],
                      ),
                    ],
                  ),
                ])));
  }

  @override
  bool get wantKeepAlive => false;
}

class Developer {
  final String name;
  final String imageUrl;
  final String description;
  final String url;

  const Developer(this.name, this.imageUrl, this.url, this.description);
}
